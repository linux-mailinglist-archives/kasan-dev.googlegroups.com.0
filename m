Return-Path: <kasan-dev+bncBCMIZB7QWENRBJ5R5XZAKGQEFA62YMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AFFC174C19
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Mar 2020 07:39:37 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id q5sf5098512pfh.1
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Feb 2020 22:39:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583044775; cv=pass;
        d=google.com; s=arc-20160816;
        b=cBrQiQOEZlGEXKei4Wy+R88H16c126dQWhtVa1ivklp2BLCbLareJMhp3mZazy4v8i
         R31C/81uRjzxRh5m6jAsHsb3Uyr+DVXnPVLP7vs3kjwaV3/jL1UQ1yjVi2n5VPpnPqWB
         +B/UoDtRrWO56ppqAQ2kbmBtbvLaNkiZ2L3XK66obwqGqgppZqJbYI2PAPXKGPcScklY
         TUm4nkWXoHZxs4dfTNPIU31722qbP/ZpzXXlqlqx3y7biBFPAW0cbH/TobOUmFRGGAcM
         47zo0Jq36b6ptg51BAz2oM1aUKcfu2a442UEgjtIuaplYjOG6NXLtsxk349TpaDPuX1+
         7coA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GhoSAt1wctWD/yqup3fN/jgPe3m2pv2SHdTi2bcyDTQ=;
        b=LZQen1cRjqqCs+sd9WAPOI8dqrRU+wnj+1paI4EPBdgXLAJcuibhhiuuQjw3XBIQTQ
         rQ307WMtVYfUUE7BKue8QwvU7hPO2Is7/X6KFbe/KNfIdhQ3h6j6wVN5nvPbSyt0buSf
         J4akIb9pGBBTCKCr0UlhwVRc0IU5uE4Lhk06wnu73UpyXP1YO6Kkh2GdrXIwB+sjuikL
         /zjIgTay7ON+k6844ho0ruDH3Emb2/bm9bPgNQh1PC/CYGz+j13EedwZ4SLFtZSXpXvr
         T5Yducev65xLPYZH0gF5pdlywOL//8dwIodkbvTNBLRWbrEFz506j0Ek5S5H8mRW5d7p
         lgWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uigv0uke;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GhoSAt1wctWD/yqup3fN/jgPe3m2pv2SHdTi2bcyDTQ=;
        b=Q4etL16/crPrEUJ6AoP2Dk1uvamirAHxAIEfYHr6rmj+SgmdmwH+tZHZbqN9DXxHn/
         qPbQBbFQLPvuvWF5ykUm9Ww1RoprFpZX5FDtT20ehkId+fEHzNlMzWVS62EybDK91Rkb
         bOqsqjNzwmU4u8nF4PUOUS54W+qbgVEYX62eV85erOp4QcbqC1PiKMqHm7oHYW65eAwD
         5KWUn8yctBZ6Ss1quilqX6RhxWAbhlujsj+si444y4hGPeDVlRXyqBDRleh3MxlJI1kc
         zH7wKzu0gXVyR7eDtHt0i/0rpNOIliyUZ5CtYONiw0MQ3ofbBtabvA6dMPXxdPNGHif9
         OB1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GhoSAt1wctWD/yqup3fN/jgPe3m2pv2SHdTi2bcyDTQ=;
        b=YuF8gMpQr+DJXZn6XRH4qHHq0DZv9Q9JBwNJobsidcWmH3Zh1NjP9TEAhevNqh20vI
         4y3ECSqQgz1uwRZ4KnYTg4xGD25/5JHZqyuXRJFLOxK8lwc+8kMcSajSbpKGLMemXb1E
         3O7FUwbzqtNAeH+LMb6jwP6YyAvlyi5H8Yf2sLMPLZsKKMZKHny2hz9InIOe8Ne6KmL1
         ZpK/fz3i6Xbv6qAUlgKsG+MqEKF4GpZYtMHex/zwgnvXx/ohE+zvP3994iJPPAp5fUdj
         kUsVHlQt2Q7ynVPFP9n2pU3WreLia/tNXGKp4gW3BEd/Prq0P5OcKBMbbuv/hJ+n0MH1
         wa1Q==
X-Gm-Message-State: APjAAAXtW///2EvRWiQAURsPU5/HVlr2omWiEdqK4WV20mVMlXEt21zh
	x48wQW4xDK5PM5XODVQizbo=
X-Google-Smtp-Source: APXvYqyv3kRz7oR98fezWY0BmZH+naZdRN3NwMhiwrlPU12ErGqnlcal5ZNK4IKyBfdJ0QQyWnHEpA==
X-Received: by 2002:a17:90a:77c3:: with SMTP id e3mr14266280pjs.143.1583044775272;
        Sat, 29 Feb 2020 22:39:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c244:: with SMTP id l4ls2603166pgg.2.gmail; Sat, 29 Feb
 2020 22:39:34 -0800 (PST)
X-Received: by 2002:a63:131f:: with SMTP id i31mr13458275pgl.101.1583044774882;
        Sat, 29 Feb 2020 22:39:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583044774; cv=none;
        d=google.com; s=arc-20160816;
        b=SdfqtbYJI4wEFMgJrvilfxA+a6lfXda/WIsj0AvY7B0lz8mg3/hwm2sdcI8o9W/uVX
         TxSWNyh+ilNipXLXdrGFCRXYeD1f6AUlJ+QDL4+t00jn+w0DOCVyTjVyx1jBKFzCuQg3
         yD5ofhBt98yEQ1ggr04hR8KzdIUhE+HDnA0Ya9PDRcG3jGLmSEbYZ7jvsaw0apNfAcoE
         E3OmXt+YmfSj3mtKarEaHf6twfAUruuIutDIzNcxI9ANZlOFChcpzOEzqR5SuaKK62zC
         qvhXmnpvhTQJUjQc9ZHxsbGPmkE4NA5ZuqNpMk275QyBheCkaBrJYbjtHij360Ap77IA
         P3Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3vMiqgqrTzNOns9tPGStxdXw3VsNXtcnvGdYEqnF7WI=;
        b=qPA6dh1pnEezXbb4vXffHeokuaNkax1ZE9xiZ9q5oma8T7tCY5ViTF46NQw8xzkyc4
         NI0XWtKL8GbxBbIfoJT6D+kR35/Jo9+9BrZTp1SPviBvW4iTsCs9o3otdSyPnLA9yssM
         L7aaVEz2zR22pZn/KY6wX1cstWbnDDokXLu1vx7sjptu0dXay+UawTd4/u7lfRW+AyaA
         sj9X7XPg+mmzZcbOiL5ZU6Npqg5xP9RCb6SNeaHLEUV8cSAAE0pl4g/LHAT3QaJDTowx
         HlvbsrgiUM5km3ffNjpvkj2U1L1li+HGyRvqOsfgoooQ3lnatC1DuwR72FjNpX7H6SYM
         autg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uigv0uke;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id 12si279345pgx.4.2020.02.29.22.39.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 29 Feb 2020 22:39:34 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 11so7172768qkd.1
        for <kasan-dev@googlegroups.com>; Sat, 29 Feb 2020 22:39:34 -0800 (PST)
X-Received: by 2002:a37:7c47:: with SMTP id x68mr11627985qkc.8.1583044773747;
 Sat, 29 Feb 2020 22:39:33 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <CACT4Y+Z_fGz2zVpco4kuGOVeCK=jv4zH0q9Uj5Hv5TAFxY3yRg@mail.gmail.com> <CAKFsvULZqJT3-NxYLsCaHpxemBCdyZN7nFTuQM40096UGqVzgQ@mail.gmail.com>
In-Reply-To: <CAKFsvULZqJT3-NxYLsCaHpxemBCdyZN7nFTuQM40096UGqVzgQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 1 Mar 2020 07:39:22 +0100
Message-ID: <CACT4Y+YTNZRfKLH1=FibrtGj34MY=naDJY6GWVnpMvgShSLFhg@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] Port KASAN Tests to KUnit
To: Patricia Alfonso <trishalfonso@google.com>, Kees Cook <keescook@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uigv0uke;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Sat, Feb 29, 2020 at 2:56 AM Patricia Alfonso
<trishalfonso@google.com> wrote:
> On Thu, Feb 27, 2020 at 6:19 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > .On Thu, Feb 27, 2020 at 3:44 AM Patricia Alfonso
> > > -       pr_info("out-of-bounds in copy_from_user()\n");
> > > -       unused = copy_from_user(kmem, usermem, size + 1);
> >
> > Why is all of this removed?
> > Most of these tests are hard earned and test some special corner cases.
> >
> I just moved it inside IS_MODULE(CONFIG_TEST_KASAN) instead because I
> don't think there is a way to rewrite this without it being a module.

You mean these are unconditionally crashing the machine? If yes,
please add a comment about this.

Theoretically we could have a notion of "death tests" similar to gunit:
https://stackoverflow.com/questions/3698718/what-are-google-test-death-tests
KUnit test runner wrapper would need to spawn a separete process per
each such test. Under non-KUnit test runner these should probably be
disabled by default and only run if specifically requested (a-la
--gunit_filter/--gunit_also_run_disabled_tests).
Could also be used to test other things that unconditionally panic,
e.g. +Kees may be happy for unit tests for some of the
hardening/fortification features.
I am not asking to bundle this with this change of course.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYTNZRfKLH1%3DFibrtGj34MY%3DnaDJY6GWVnpMvgShSLFhg%40mail.gmail.com.
