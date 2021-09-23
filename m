Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVMAWOFAMGQE7THZ5VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2206E4164BB
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 19:58:47 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id k206-20020a6284d7000000b004380af887afsf4241086pfd.17
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 10:58:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632419925; cv=pass;
        d=google.com; s=arc-20160816;
        b=i8WIwpKXC4nh7hU241BvoajD8YukwNT/iZFSyqCXhSMGUyMTdAmB9H3zzUK807APHe
         r+pEyZxj3AzN3ScEGjwhJdV70VPN633XF/8ZVS5qMYgVMzb9Im2P/MSiZW5FXI/zQIDZ
         iA81QYc9klAqvV9CCFE/X8SqQcGM2dooMXBG3vLx4wLchxCnxfuONYLpfXNBbMqfRGNF
         jgaGU3MtXch6puRCoTbdIPNTdfgIleGVZibS582d1zAiALlwybyE7g8e12Sa/QvKhQC6
         UNqXRJDeBPASzC9Ow+althUZjmPoDqDBHi8+7Z07oF57c8UG8UF+V9qPYE3xWNtuVYCk
         xo6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Zht0TcM+A22wPcXw1ybJjInKaqgGtdDA5CO8qkIAG30=;
        b=C0JBvZbeermO864BLZzp03PCL91D9eqXddxlziGofOaxE8z9na8xHC6H2xGmker3Ys
         6LHh/IpJLuR3chpAgRiLWXTcQWOYjl7OTy7RzjB7GNGoJ2C3tnSlle9pafe3WBR4P4Df
         NST9C6hM/qEW+DXwPid/aVA0bxJ4nJt4UjXMvLtR0x176tzvmSt0YF+guBaGhMMwsG9J
         L7rHw3pRHd6IBKPD4iczpPG5fVvpdyKKpR1ET6zxqJiMxHI2R8of5vZwZ4n2a4puhIHQ
         ofWyerE9qavR0dOlaSid4Y3YaDRW6FyLZ0ySsc+b+l0pPXZqDDo8iEPwEZ7nAUB2Q77T
         4ACQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eKHRmobr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zht0TcM+A22wPcXw1ybJjInKaqgGtdDA5CO8qkIAG30=;
        b=fstkGyAbfitSSVVpPCVSyC2gPkky3uNM+5jm5IQAuo1B1S/MBnjSK189k/e3OqZMyL
         fwE/aoF0Dnz0awbxO1h81JtPzaRg+MBXiLMfwMGvqjNVhmXVufME1c6ROoS6aBamP4QP
         QKgQPQ2vdZGDiqMyR/A/pQ6gz6wmc9w2nRchlQzwEldrVz/Whks8xF53jXS4CdB845tZ
         qsoo2QrslhubStV7OyzPQ0h5Y1QTKsCrHAQphJMgfsk1m+w1mwsjAodkmeU65XsfZ6q1
         1ugbezJ8SDO6aGsnFo7XsmUk7fH7Md7hsSPUW6n8ksKwHSRdeTzeitetjJneXMwf7IG6
         8Qmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zht0TcM+A22wPcXw1ybJjInKaqgGtdDA5CO8qkIAG30=;
        b=Zb6oJGJagmHzIafWnNgDQlEAsQMQJ1oNOonISU4fWh+DxeK8GWvJRGOcE7k+QN8gZn
         Kx+eWuKrBkQhrBxBmNaZEjXsgqHqxLR5eMzu6wgzc56Y2LncNM9wcaPHcWcSY0V0QpZ8
         ImODxN+IH3w6APNkbXKzQsz6c/+TOZSzDV1AkoR699dKgIxZUpAZVRI+9v1fLmYJR1TL
         VjzSSgzpdBzYymy3r4jiC7s9miHWcJUf54hmWq73zK1v4EYMysQwVMXLdqnuIsKqHVps
         vCyA91FeiuF1SFp/1AujSjVKWIHZh4cv+D9RThzEXLHau7NMYU+BA7GVkIDwkgWI6pDP
         BaMQ==
X-Gm-Message-State: AOAM532sVRAtXmEYjJKqrCNdHMNAk1XDJJObziyD3dZutShoegWYgzwW
	GbOkjkfbpv/fprP7iIdeO2E=
X-Google-Smtp-Source: ABdhPJwePMifgZoWjy4FaK5N2/w9Ta6AKhKf0XnlA5y8dIDIR79XO0hzNvX7j9luyAW0UFbdXoDaIw==
X-Received: by 2002:a17:90b:4c86:: with SMTP id my6mr19202373pjb.176.1632419925577;
        Thu, 23 Sep 2021 10:58:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7d11:: with SMTP id y17ls2510858pfc.9.gmail; Thu, 23 Sep
 2021 10:58:45 -0700 (PDT)
X-Received: by 2002:a05:6a00:22cd:b0:43c:9b41:e650 with SMTP id f13-20020a056a0022cd00b0043c9b41e650mr5521208pfj.60.1632419924986;
        Thu, 23 Sep 2021 10:58:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632419924; cv=none;
        d=google.com; s=arc-20160816;
        b=cE/xrE0+zbAeVfYzljGcQSG1qYF4avuP3Fo15jWb8SlG/3AUAZgYhNjewr+m7HyEwh
         PFUGmG2DZmebjH8Jc9IihPeNFRP55p4aRpS7R5ig8Ud2GZf9VN++ikrxhRxEc4d6xr/I
         a+aV8ZK0BJTi3PLq8Q5LI68S3Fc9dj1wMcaoH2vgM+uzvH0tSvLLveza9cmumwyKWN/X
         VAQlDDdzAQSNB3Dbm7rFn0Zen68WWnOODezR6dMwAj8mm0cKfdAwm9tIyV/KkErntbRh
         9zAxRHLCXCnsob26E4DYdzulOvzDgNNqtKfAHjxnZYmLL8tf2EC0nDiBJ9ko2I5CltRi
         CG7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/JGn7mZwyWEwvBIvgUj4s0mm3yX6tvXxieiY/3sFb9c=;
        b=b5X74gZyBi4b85j0Gh2besirKcv9GVyBnOj4VSei0tk26DLEAqOQTxCq/Gbkc+u1WI
         NBiDn7IYZ6XCCVzbfJ8EM8nf+CpKkPqC7ir4Rj8QjgD1UnpVoRhrwo4CE2NzXX1fs+kh
         /skE4/IQMm9bEQ/Mg/yOIwoWmO2GNhoGf5x3etTvN5Y1wTDxZgJrA5j4OC0cGl9kLx46
         iKRLJOx5mtemEmGzLS0S9E0ipLSwsSCUA8D3OaWJ6Mlbv3BXrnXeNv+uTPKQpXaM5e48
         YnmEY/h/kDnxogCjuRLKVIS+SjvCUocZthm/e2Mr2w18zbX9pd2GDOgdfpdgrRBPmfc5
         3EPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eKHRmobr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id r14si153844pgv.3.2021.09.23.10.58.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 10:58:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id s69so10732669oie.13
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 10:58:44 -0700 (PDT)
X-Received: by 2002:aca:db06:: with SMTP id s6mr2697081oig.70.1632419924159;
 Thu, 23 Sep 2021 10:58:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210922182541.1372400-1-elver@google.com> <CABVgOSmKTAQpMzFp6vd+t=ojTPXOT+heME210cq2NA0sMML==w@mail.gmail.com>
In-Reply-To: <CABVgOSmKTAQpMzFp6vd+t=ojTPXOT+heME210cq2NA0sMML==w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 19:58:32 +0200
Message-ID: <CANpmjNN1VVe682haDKFLMOoHOqSizh9y1sGAc4dZXc4WnBsCbQ@mail.gmail.com>
Subject: Re: [PATCH] kfence: test: use kunit_skip() to skip tests
To: David Gow <davidgow@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eKHRmobr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as
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

On Thu, 23 Sept 2021 at 19:39, David Gow <davidgow@google.com> wrote:
> On Thu, Sep 23, 2021 at 2:26 AM Marco Elver <elver@google.com> wrote:
> >
> > Use the new kunit_skip() to skip tests if requirements were not met. It
> > makes it easier to see in KUnit's summary if there were skipped tests.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
>
> Thanks: I'm glad these features are proving useful. I've tested these
> under qemu, and it works pretty well.
>
> Certainly from the KUnit point of view, this is:
> Reviewed-by: David Gow <davidgow@google.com>

Thanks!

> (A couple of unrelated complaints about the kfence tests are that
> TRACEPOINTS isn't selected by default, and that the manual
> registering/unregistering of the tracepoints does break some of the
> kunit tooling when several tests are built-in. That's something that
> exists independently of this patch, though, and possibly requires some
> KUnit changes to be fixed cleanly (kfence isn't the only thing to do
> this). So not something to hold up this patch.)

I think there was a reason we wanted it to "depends on TRACEPOINTS".
If it were to select it, then if you do a CONFIG_KUNIT_ALL_TESTS=y,
and also have KFENCE on, you'll always select tracepoints. In certain
situations this may not be wanted. If we didn't have
CONFIG_KUNIT_ALL_TESTS, then certainly, auto-selecting TRACEPOINTS
would be ok.

If you can live with that, we can of course switch it to do "select
TRACEPOINTS".

On a whole I err on the side of fewer auto-selected Kconfig options.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN1VVe682haDKFLMOoHOqSizh9y1sGAc4dZXc4WnBsCbQ%40mail.gmail.com.
