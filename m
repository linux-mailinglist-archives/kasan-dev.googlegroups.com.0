Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR7RW2GQMGQE2Y3F7ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 048154690B0
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 08:16:25 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id v16-20020a9f2d90000000b002e18753e8afsf5715007uaj.2
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Dec 2021 23:16:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638774983; cv=pass;
        d=google.com; s=arc-20160816;
        b=uR7K39Z2EMfRku19OPDc2KyhZIFIhDWqF1gwhNZjQetGiI09L9442J2GTSAShdl93G
         C5oUn9FVLM/9GsdYviSozspqHBe5V/32B1GbGA9m3nKGMVloxEnNfC01YkrtMKsnTzh8
         VidjB3cD4J6pFsNlPi2/7jF7AFU8Ou/dcycwHqKGlvjWVl46aHE8x8pAmd13i24bSAGo
         0u+YqwJzQLfLsTip3jSIYQ+QQB8kLYihHK3cZrVDDBAKEZYZvp/KtGlzpuh/HveV70zl
         3M8TsJyJ57mLthOqsMKxKCe2PdqbkPYZNyLvvTOFpMdOjzVO6CZ8JxmNv7gg36M73EKX
         9AzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CaYxjwm1EUO1L1k8w7zQKyKbg5WT54SRNV+U+aHcu1U=;
        b=ck6jwsdVnTZDJgI1kta0tZVOseMS3LisxtP11rq4L8+Oben9QZSOMgPtqxcG1oNtW7
         jf/LfEvkddC/V9lSrtGCuf+TfGzLRherR7KmRNjpdbgN7mSme3eCE6mn+g9cFYQyfNVG
         BoUku/6kx9femcohRlRUGoyGBU7ce/Q93lyrqoFOneYhGkpaxDgEWPhfdS6ObTdR6JeH
         lWqvvwDvlYbfgFmTF9S8V/QPgnNJOYChypHCoa/fQtRSSkzv7nWJIxK30MrFpI+b6gsP
         JEQysuL3XXrTQLETF3fY5nVmYTS5xLT6Kvx7G34bJ0txHyLShlR/R/dFAHqT2INpug28
         7c9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XEkNxxxq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CaYxjwm1EUO1L1k8w7zQKyKbg5WT54SRNV+U+aHcu1U=;
        b=YCj7mL/IwbsMyZ3ie0SNWk/VJ4YTA5jsbtpgqhyIeWZKL85H3jLVTenh0cduF0995Q
         aE15K5yZs396MsSS3njq9UaltbgTpNuT6YhCLdvl4zNWgrXQ18+ZZvY213eFwI/Avsh5
         YnMi/omqP1+r0QoALy/XIw+rwVwwYO9bQuO5VDw4WzM1Y+VFQFdork4Eb2CHfJhMqMV7
         /qCF73Ej9Z1hFfn/kQB6GS4HXjOK0hnpV8SH8RHshW4r4pdnkhbLS43dVUn2Y+wYcHUe
         B2x3Jd2cj38TIKL8qYy8PknfVU0nABXqPZOM9YM3/nVBkbLkXXLS6rq38k3nQwLYaadG
         v4Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CaYxjwm1EUO1L1k8w7zQKyKbg5WT54SRNV+U+aHcu1U=;
        b=aE8wrI4/O31GrOTSQ/+nnjpzt+E2zdV6XDcX+WifIzFLzBK6vo8Zr1jelWcYj3cE2Z
         fYAqsWquO8Phyx0DXEDO6LeY0W/1IBgvkQ2FDHIBZ3IdCPQtNrZBrDttbfvlJe7VnOZp
         hpyU2Q3iAvYu5+0z8hEiU5NJ/ZuWUCqvn5SwPnxKnr4/XQ0Q5gk9uiRJSOls1ra7YIb7
         rGIMHPJQX/UzKFHxxcy5sG3bYfkxiXMa6hc+Rgavb/RmisdWroAfEK3APEBsEs3yJyie
         o2Y01MavghmeZiAqzKJLlFrRFY0PnQ+9iMaflc115dvCbNi8X018k0qd65OreXuuh8Al
         YW4Q==
X-Gm-Message-State: AOAM533INJccorePvXbOBoxjo73ybraRjosKZ24YTDmp2xo0M1Nq4hZn
	uzFGGjtIb9avWkhSg20G2oA=
X-Google-Smtp-Source: ABdhPJyCkAGd2hl0iUedXMTKG86Six0SNmapIAQPHUlq+z6V/XQgblmZ/yFvQrjG287XY/tqHACwcA==
X-Received: by 2002:a05:6102:a46:: with SMTP id i6mr33757100vss.19.1638774983805;
        Sun, 05 Dec 2021 23:16:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:208f:: with SMTP id r15ls2129914uak.7.gmail; Sun, 05 Dec
 2021 23:16:23 -0800 (PST)
X-Received: by 2002:ab0:7c65:: with SMTP id h5mr38419440uax.138.1638774983321;
        Sun, 05 Dec 2021 23:16:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638774983; cv=none;
        d=google.com; s=arc-20160816;
        b=OpEVuSHklly3KIi9rokRLwx8dJMZU7td7c3j4B1TV8FKjaGggf4VS46QYN7g5XZzcA
         OEOOt9X2dKHMV0YWs//LgoGXYNbb+8iVzdeG0fLPzodCUo97tXLq5ob3ZewfpgKVwflA
         PmrBVS1DtX0AMOhjC478imw7yv6pLhenFmObhfzSezubhIXWbOZv9zbCGLKksSXDjLnM
         ln2+bNpGho8BS9WN70+FE1aparkKBhp4/j8ojhFjtCV8RQf4yySVwbnpqRSHBiYkzGVd
         dcuiw8/8vTCPSyv5IosXjVg9lJc0A6Cgd7e41ZrE+1ZTu0k6NBU70mQEvyaW4k+/eHj2
         +WQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kMt90pKBGW/au5Bipth7kSeTJYiTzTjqmOMqmPuidYA=;
        b=aF9aQ7v4B1tR8Q/uhmtNi+dXGg+iuKv9P8ty6kuj5bO9v64chFBVgHt1EWTB6FIZUB
         GYLRD/Yz8z4iUAUkq8YvA3+i9iss6PcrAmpx4TUI0P7QJ2hasVIIW6ozlug6R03ABsmj
         HOMaalE153IWdxaSBSKaFmHBXI7XuWg+4fJWKr/XGQJ5Hj6zVrV7GEK9xbYl1W1HDcmw
         cBCYG9G4R9VKWW7ampPiM9zvH1/cVikkWkQyjI/NFdpoNCdm4ZTpf9O4porkfJQVopVw
         Xw9ViY4WkBEMwhdeCC8tOgU4dT2Ljw0jqMGfzpm7JA0OgoZckJiIP9ZYuZVBWfkRquYU
         10FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XEkNxxxq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 15si533257vkc.1.2021.12.05.23.16.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 05 Dec 2021 23:16:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id bj13so19864489oib.4
        for <kasan-dev@googlegroups.com>; Sun, 05 Dec 2021 23:16:23 -0800 (PST)
X-Received: by 2002:aca:af50:: with SMTP id y77mr22543199oie.134.1638774982675;
 Sun, 05 Dec 2021 23:16:22 -0800 (PST)
MIME-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com> <20211130114433.2580590-9-elver@google.com>
 <Ya2Zpf8qpgDYiGqM@boqun-archlinux>
In-Reply-To: <Ya2Zpf8qpgDYiGqM@boqun-archlinux>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 6 Dec 2021 08:16:11 +0100
Message-ID: <CANpmjNMirKGSBW2m+bWRM9_FnjK3_HjnJC=dhyMktx50mwh1GQ@mail.gmail.com>
Subject: Re: [PATCH v3 08/25] kcsan: Show location access was reordered to
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XEkNxxxq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Mon, 6 Dec 2021 at 06:04, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> Hi,
>
> On Tue, Nov 30, 2021 at 12:44:16PM +0100, Marco Elver wrote:
> > Also show the location the access was reordered to. An example report:
> >
> > | ==================================================================
> > | BUG: KCSAN: data-race in test_kernel_wrong_memorder / test_kernel_wrong_memorder
> > |
> > | read-write to 0xffffffffc01e61a8 of 8 bytes by task 2311 on cpu 5:
> > |  test_kernel_wrong_memorder+0x57/0x90
> > |  access_thread+0x99/0xe0
> > |  kthread+0x2ba/0x2f0
> > |  ret_from_fork+0x22/0x30
> > |
> > | read-write (reordered) to 0xffffffffc01e61a8 of 8 bytes by task 2310 on cpu 7:
> > |  test_kernel_wrong_memorder+0x57/0x90
> > |  access_thread+0x99/0xe0
> > |  kthread+0x2ba/0x2f0
> > |  ret_from_fork+0x22/0x30
> > |   |
> > |   +-> reordered to: test_kernel_wrong_memorder+0x80/0x90
> > |
>
> Should this be "reordered from" instead of "reordered to"? For example,
> if the following case needs a smp_mb() between write to A and write to
> B, I think currently it will report as follow:
>
>         foo() {
>                 WRITE_ONCE(A, 1); // let's say A's address is 0xaaaa
>                 bar() {
>                         WRITE_ONCE(B, 1); // Assume B's address is 0xbbbb
>                                           // KCSAN find the problem here
>                 }
>         }
>
>         <report>
>         | write (reordered) to 0xaaaa of ...:
>         | bar+0x... // address of the write to B
>         | foo+0x... // address of the callsite to bar()
>         | ...
>         |  |
>         |  +-> reordered to: foo+0x... // address of the write to A
>
> But since the access reported here is the write to A, so it's a
> "reordered from" instead of "reordered to"?

Perhaps I could have commented on this in the commit message to avoid
the confusion, but per its updated comment replace_stack_entry()
"skips to the first entry that matches the function of @ip, and then
replaces that entry with @ip, returning the entries to skip with
@replaced containing the replaced entry."

When a reorder_access is set up, the ip to it is stored, which is
what's passed to @ip of replace_stack_entry(). It effectively swaps
the top frame where the race occurred with where the original access
happened. This all works because the runtime is careful to only keep
reorder_accesses valid until the original function where it occurred
is left.

So in your above example you need to swap "reordered to" and the top
frame of the stack trace.

The implementation is a little trickier of course, but I really wanted
the main stack trace to look like any other non-reordered access,
which starts from the original access, and only have the "reordered
to" location be secondary information.

The foundation for doing this this was put in place here:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6c65eb75686f

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMirKGSBW2m%2BbWRM9_FnjK3_HjnJC%3DdhyMktx50mwh1GQ%40mail.gmail.com.
