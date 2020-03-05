Return-Path: <kasan-dev+bncBCMIZB7QWENRBQ57QLZQKGQE6OJLQGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 22B5417A014
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 07:44:21 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id w76sf1681478vke.20
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 22:44:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583390660; cv=pass;
        d=google.com; s=arc-20160816;
        b=vukvJ1LC488V3ptCpLr+H3QJgiVqmvVM+O0Jnl7Gd2Rbuy3YhDQ0gv4oAw2zClENpR
         gi0eIHa3JfdJTxi9geRZ28LIcSmAeP2zGpM+w4HbO03ePVBW7I8aT+L+dWLJ5Vm7W/ur
         LkFNhMPfJSaTc8pghd6PfelgEdKh/C5uY+lq2cONz12ebifbZfz2HXxjaUZb7/mCZSvL
         iZrSn72P3mBvvcL1WlnCPPmEq0jtqAqQxP6vjBpnEpPYXKKZaag9HjKXkWopO54R5bTX
         6mVg/IrcqDqHSOCW9pRo1OueRt0BHizK4mLsl6BbTGJp1mPGCQ+RfFTEvF3Y6fODN1SA
         iBKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zaEzFHxD/NALUqiYLNLZNRmK2L/h9naMJMydhItmwfU=;
        b=O325ZT9Dy6jlPitM6+cPXikrl1AXq/i3+ajSkuE9I5YMiFHwzN2VuAPUldAzHc4IwK
         2U0xMUN1DszalXxgtBUVGqqUsGBSXnmId7m6TusKQ6LbX0kyMnhJnHbSnbJwlNhMj40G
         dYnw/5OHtBQJbxDTC4THLCbw27VEydLlnCZSzrJGvIZrCQE3CFjGIbbMjTmlTSlBIxVc
         3uF/wvDql+Nsi5RyDJz104Z8sg9qwjJDP4e7pPfTBf+q3TXiP+TnEGeTjlK5c+WZSlev
         54hJB7Zc9YZ8My/QOdpvKh9lR3aStQFLgB0Lgszt6MMwkeXs5q2uRrrhHYknErcyDX83
         IQOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ctYxfjLo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zaEzFHxD/NALUqiYLNLZNRmK2L/h9naMJMydhItmwfU=;
        b=O+jeOMArbQX17JX82qJK699l8k5dG664DbtHJS11eeCWI/JxtCMxFyFZYNTr+qp6Uz
         mIIuPDO+eKMdh9AShvM+OGfxusOmQmafL+2ESYl1JwKmy8/n0/R7PRA4f3QVjCHR5KZ6
         LDjYy4jykTg8d4f9VM1c1D6Kowu6hejciNPt2D9oRd/FnA1gQL9CM0nsTZ9x9E8oL/RL
         gBucaklSwcoQOkpDeeFg/h7SUDkZF1BFKPgGy+aE1cGYmJddZK5P25PFtqAFMv3fn1bt
         nQ0Lw3Nw0JPNzK8aatZHHHyrrEfE0tvnk+M989YtEPGodkmqaRLl4kXRTbZHqRY+2lpG
         yZHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zaEzFHxD/NALUqiYLNLZNRmK2L/h9naMJMydhItmwfU=;
        b=WrgTDLvR43mSLocnQ+EGE0uOMUqJoMIokHJJo9+5lheEpBrM9UM4kojgUPGyIDqG4a
         cnvUN7t8Je/daj2BT8ZBN51h96Y0VkVdTlORTY9ytO+JiUE+J2UxMHGUR4fTAFrAe5vc
         50S90Frmn4PcacOU/5fFGrd1NRd7eavD9rtPKbVE3WzoF2ISgAwr2YlzY8/aXzblOBeC
         gx9/ySe5pVPeRzSbho0xiEaZG3F3Z/yIP6i4620Mdxpt/nUFwXujDgYpQNi7PmZLr2Kj
         oysYTkS8qm5tL/AgPAm3grlzKWBtZYBNNEdwBYWR7sSNHZzl7G4ehK+DZaod2KsMgeEB
         NlEg==
X-Gm-Message-State: ANhLgQ1fxuw+pxZ61eR3UinjYQur3coDxBoC6jHLs4yfmW0jx9fJimpQ
	NcHyGqeLU0a2H0/QqsCleN0=
X-Google-Smtp-Source: ADFU+vuE6tb6wgKSIWivJvp5v8zFM1U02qzmkW+eTDF6pqwPHIeIiRTCHtGfNF3YV8Z5XFJ6QRnngA==
X-Received: by 2002:ab0:7518:: with SMTP id m24mr3642614uap.60.1583390659872;
        Wed, 04 Mar 2020 22:44:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fe08:: with SMTP id l8ls144019vsr.4.gmail; Wed, 04 Mar
 2020 22:44:19 -0800 (PST)
X-Received: by 2002:a05:6102:308b:: with SMTP id l11mr4164217vsb.68.1583390659455;
        Wed, 04 Mar 2020 22:44:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583390659; cv=none;
        d=google.com; s=arc-20160816;
        b=dd+zx/WsCCxHJY3J7bdrtv7yDt6mIdCHHQEMKN1PjuQCAB3nqHFkyqPDOVIiTR0oMl
         QzLQHYAtAeLO9u4hFiPrP0/F85xEHs9AMKigV+/vghR7/48yc7J2RKeIsyCpcjWbzmX/
         MLo+36+Psv2uWdc+unH7IMgizOTooQKKMvkW8n0snYWSZV7RL+YZsQv4ROabBtOYsZ+P
         WLWsBlZU9e/BkDxUOAOHrDwO8Sj6pRzknIxf7nG3zIwO4K8/FFtPJGJGP+jm3p4O6q+r
         fQYEBUpcn63u1Zy4UH+TDYo+5tSnCDhaYzrW31zdf1Iu9yLpKqfTxj3LmmsdTWfuprg0
         E9Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jUsXfxq47fTB69Eo8JioRupR5VCGfY6ptuLWDAnbRk8=;
        b=rYdYaQj61PwkuWw1sCmPdLP3o/HkfR57+OxfhRn0/jWRbrbzk4eIv9CtWqDzy/l5OU
         rzGeaM1bw93177e3LET5Ve+uy65lFh1CsCTVA/98WMt8m/hr4JtJZ0Pjsa8yVS6NwS8d
         npFG/zjEk2Yw2tka5Da3noVpqle9F7SaTIKekx8PYAOL+IYRwMNfyF+rCs71C/hcKwKp
         69XFiPHPyhVYP7Z/kf+jzCQw86Prg83024LZkIgvplS6iLspoMWO5BxL1fYooA9nnERE
         ArMalrlqMj3i80s4MxEvlwb3aMllO9r3yeHXSEhKa++XCc0Q6RP5qF33a9sr52G7nKfU
         loTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ctYxfjLo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id f20si224574vsh.0.2020.03.04.22.44.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 22:44:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id p3so1977821qvq.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 22:44:19 -0800 (PST)
X-Received: by 2002:ad4:4bc6:: with SMTP id l6mr5269372qvw.34.1583390658639;
 Wed, 04 Mar 2020 22:44:18 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+YFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg=pxZv8uZA@mail.gmail.com>
 <CAKFsvUJFovti=enpOefqMbtQpeorihQhugH3-1nv0BBwevCwQg@mail.gmail.com>
 <CACT4Y+Y-zoiRfDWw6KJr1BJO_=yTpFsVaHMng5iaRn9HeJMNaw@mail.gmail.com>
 <CAKFsvU+ruKWt-BdVz+OX-T9wNEBetqVFACsG1B9ucMS4zHrMBQ@mail.gmail.com>
 <CACT4Y+b5WaH8OkAJCDeAJcYQ1cbnbqgiF=tTb7CCmtY4UXHc0A@mail.gmail.com> <CAKFsvUK84pD+K5rTbvKXB0MyW9XCknpSfMAO28iQ4S1=WBQK6Q@mail.gmail.com>
In-Reply-To: <CAKFsvUK84pD+K5rTbvKXB0MyW9XCknpSfMAO28iQ4S1=WBQK6Q@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 07:44:07 +0100
Message-ID: <CACT4Y+a+SLAetVsquiitua9v0pnhQD-C5AWFekvZ8h-m0y1xuQ@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ctYxfjLo;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Mar 5, 2020 at 1:08 AM Patricia Alfonso <trishalfonso@google.com> wrote:
> > > On Sat, Feb 29, 2020 at 10:29 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > >
> > > > On Sat, Feb 29, 2020 at 2:23 AM Patricia Alfonso
> > > > <trishalfonso@google.com> wrote:
> > > > > >
> > > > > > On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> > > > > > <kasan-dev@googlegroups.com> wrote:
> > > > > > >
> > > > > > > --- a/tools/testing/kunit/kunit_kernel.py
> > > > > > > +++ b/tools/testing/kunit/kunit_kernel.py
> > > > > > > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> > > > > > >                 return True
> > > > > > >
> > > > > > >         def run_kernel(self, args=[], timeout=None, build_dir=''):
> > > > > > > -               args.extend(['mem=256M'])
> > > > > > > +               args.extend(['mem=256M', 'kasan_multi_shot'])
> > > > > >
> > > > > > This is better done somewhere else (different default value if
> > > > > > KASAN_TEST is enabled or something). Or overridden in the KASAN tests.
> > > > > > Not everybody uses tools/testing/kunit/kunit_kernel.py and this seems
> > > > > > to be a mandatory part now. This means people will always hit this, be
> > > > > > confused, figure out they need to flip the value, and only then be
> > > > > > able to run kunit+kasan.
> > > > > >
> > > > > I agree. Is the best way to do this with "bool multishot =
> > > > > kasan_save_enable_multi_shot();"  and
> > > > > "kasan_restore_multi_shot(multishot);" inside test_kasan.c like what
> > > > > was done in the tests before?
> > > >
> > > > This will fix KASAN tests, but not non-KASAN tests running under KUNIT
> > > > and triggering KASAN reports.
> > > > You set kasan_multi_shot for all KUNIT tests. I am reading this as
> > > > that we don't want to abort on the first test that triggered a KASAN
> > > > report. Or not?
> > >
> > > I don't think I understand the question, but let me try to explain my
> > > thinking and see if that resonates with you. We know that the KASAN
> > > tests will require more than one report, and we want that. For most
> > > users, since a KASAN error can cause unexpected kernel behavior for
> > > anything after a KASAN error, it is best for just one unexpected KASAN
> > > error to be the only error printed to the user, unless they specify
> > > kasan-multi-shot. The way I understand it, the way to implement this
> > > is to use  "bool multishot = kasan_save_enable_multi_shot();"  and
> > > "kasan_restore_multi_shot(multishot);" around the KASAN tests so that
> > > kasan-multi-shot is temporarily enabled for the tests we expect
> > > multiple reports. I assume "kasan_restore_multi_shot(multishot);"
> > > restores the value to what the user input was so after the KASAN tests
> > > are finished, if the user did not specify kasan-multi-shot and an
> > > unexpected kasan error is reported, it will print the full report and
> > > only that first one. Is this understanding correct? If you have a
> > > better way of implementing this or a better expected behavior, I
> > > appreciate your thoughts.
> >
> > Everything you say is correct.
> > What I tried to point at is that this new behavior is different from
> > the original behavior of your change. Initially you added
> > kasan_multi_shot to command line for _all_ kunit tests (not just
> > KASAN). The question is: do we want kasan_multi_shot for non-KASAN
> > tests or not?
>
> Ah, yes. I thought your first comment was suggesting I change it from
> printing all KASAN tests by default because the intended behavior of
> KASAN is to only print the first report. I think I'll pose the
> question back to you. Do we want kasan_multi_shot for non-KASAN tests?
> For functionality sake, it is only required for the KASAN tests so
> this is more of a judgement call for the user experience.

Good question. I don't see strong arguments either way. So I guess we
can leave the current version (only for kasan tests) and wait when/if
somebody has real arguments. I wanted to point to change in behavior
and understand if it's intentional/accidental.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba%2BSLAetVsquiitua9v0pnhQD-C5AWFekvZ8h-m0y1xuQ%40mail.gmail.com.
