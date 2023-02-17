Return-Path: <kasan-dev+bncBDW2JDUY5AORBWNCXWPQMGQED2SQBLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id ED3F969A8CF
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 11:05:14 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id x127-20020a633185000000b004fac0fa0f9esf241706pgx.19
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 02:05:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676628313; cv=pass;
        d=google.com; s=arc-20160816;
        b=rT8Pe86RpQAtnk6Qm1s6Fsz6nA/04vS4kFG6efkzjtc5m3bHekJf2q6vnA740UCrL7
         DLT5e2GHj48Cw5hXU4eRAO0J5XsxRgXIGqVQYGiorxxAviO8iSCg+gXUpxGDr/LC//+P
         vbvoakGCXhbPtP25/MReRmn6CPvdB2uooHHUaUPd/rwBFb5LTlYsjrBnptQgIJq/utbP
         Mc3OGgAtLxJ5jK44NzzNRFLV6vJoiceXtpdPU2rqKdru1e/cNSiXfHOQorf2G+ijGYtS
         g3oxy6g+XdY9pfHTiK0urW1kNhcYXT3AZtHo4riBLRJKZ6i+PadxeB2VMs2thAPpXSiI
         4aPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=lyuF040eecdEULl7dSAuq7Lr3fqdrR5ekrNmqBj3OfU=;
        b=Ljn+5RJvz8UYKRV8lCSnR8oZB3mTldufyvoTcGWYQs6GrvJs1JlT/BrGQjRZ0a3dKI
         VyyB236xkM+AggB4UxmaGV7lkVbc8Cdp3NuxShCUTyU5hEIp8NLIwmPhAO8cBJ+zYdfa
         2JSTXnHps1MsoWteHtSzqBzAWBWta1jct0dwUoRRe08zbAxgCm23wSgi012ZFHaUUDE0
         q2yKtUPPk00Q+3sLgKLeFKQ4Au72uDv7aaHNKIRSYSvY9X/YjHWLD29unowurOQy3LXN
         QA+V+mrEITAgl78213Sy+uzNM+6Sx+KBklgQd2WaXFIQkSxk+FmULxD2586LylGvKHP5
         5V+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=i7htHyT0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lyuF040eecdEULl7dSAuq7Lr3fqdrR5ekrNmqBj3OfU=;
        b=hL/4mzmMQcViMwhdc8fKIsyoQy5C1moxasw6ZGTj6dQjA8VVtpf32zADPDizCa/z0S
         uHw5UuGRDCPJXSjgbMfIi89PtBHm6E3GxbtIirUvgPTqVhv0ePtZRM/A5qnYvvemJCoq
         1oLnKayJ7wp5i65fxlyS31IomHyS3NgrOV+rtpR9EhJSQaxwaBlk6+tQKb8oLqFuvK4V
         4nms8qmyO1f3hPJNeyQFHRbXpSk5kXOtT++9coviiXsOX7w8KRDCJKglU0Zt1zkUmbvo
         FpViM6nwCQktEj4BthJlKuhDwLmYzS+enlwozHuAXhlz69RzH5lueLYaitS+sd9Fg2SE
         +vFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=lyuF040eecdEULl7dSAuq7Lr3fqdrR5ekrNmqBj3OfU=;
        b=fp39F1OwiRfLnGZCIc1Zf6bFLb/PO80DtcnGmT97Ws7SP9BpwmLFfMZXWe/vPcLhvy
         WoBoeesPQCbWLQoecDR0ys0baJo74PEJu45qxOBwFb0YihSAGuOPJPzBlaUj+DXuM2dv
         PdEIhlBPQhMrElXv3b7c2JxmIfd4gbWUKuM0v8imaoeTqgoLw4xjHuUkSvLJn3KEHXuE
         29rxsrsk3hRVa+m3bHEA0/b0imJ44yMsHI9j9h60p0GwGfR9qt5up8N5Slt4iWz6HfEo
         c89FGt05b9H/wWF+tIcnoFicV9Aq9ZxwJJPsHZGFCQ/ENRV/gCCXjj9lIOo5ZujlxB29
         l8gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lyuF040eecdEULl7dSAuq7Lr3fqdrR5ekrNmqBj3OfU=;
        b=bsNI84D4/Voeak4l+vjk1SW14YynX8U5ru8jlx1W+iymxvA9yNcvko9xEFREz3x/MP
         TLxBm42a+GVpivYkE7G8fPLCFz3jHldwR+XzzU2/i1SyHaX3wugsR/i/kc8E5KtuoBuL
         CdCtEC3hsTvpbnnDQc+Qx26IZ+KFbkhiRKRpPG+x/injodkQnxMcObAw7yYjZFAOl2DU
         8yGwN8/YdqAiMOL9SAI3GIEijRgn1+8hhoIPl71wp7hRbEEzulTHQnYRl9S0rEq7GCD4
         iIcRPsNaRKlnPvx9XN2ovDN8g0GlSCqDZuFbKmMfhawFmxviZtVCaBMDcU5Usnq2egl6
         duLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVwU6QmZ5aqtWtUtYAq8+cHJJW1XSrbLqz2l2R+Vm6Ir9LxzAWY
	VUvx/3Epk8cqP0S09P36AWQ=
X-Google-Smtp-Source: AK7set+lBYbmzcCiSb2uaqtOHR3Zn9Me77Fb0kjy1KhsdBB/OhG5j47/QyJG7jB4bLHuYCCju0bI6g==
X-Received: by 2002:a17:902:a386:b0:196:433e:2378 with SMTP id x6-20020a170902a38600b00196433e2378mr141776pla.4.1676628313277;
        Fri, 17 Feb 2023 02:05:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3703:b0:234:d72:dc58 with SMTP id
 mg3-20020a17090b370300b002340d72dc58ls2538421pjb.0.-pod-canary-gmail; Fri, 17
 Feb 2023 02:05:12 -0800 (PST)
X-Received: by 2002:a17:90a:34b:b0:233:9fff:888e with SMTP id 11-20020a17090a034b00b002339fff888emr963963pjf.39.1676628312503;
        Fri, 17 Feb 2023 02:05:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676628312; cv=none;
        d=google.com; s=arc-20160816;
        b=PWgsbXOf7R2aXkfULRGY78ZKKjSwSeCC8IO/ehKECx1wcLtCAdsM3X4BURsotFiBn6
         2vTilwEoIvdqFkhnK+r8yewNiizD9MdxPM1Ifl15Dg94QE8YgmJ62pTmakCUMX6GKysi
         fmDeH93W73xBiCjJS2e4NjQUiF0Wt2w8hiyZfqLoGdr6t8xwmhQy+clx/Q50sIgqolEU
         tU47ZHzcACh9cf2UcC469bqtnwqqJYl11Uom6UYeHPJYXCgYFoD0ni2TuCsN37vDScw+
         +yCUNGxRxEGgPy/pNZZwdUQBoOzYKzrulfB3Wm/H+6zA/T2CYfXvb6yOAuWYWPq3+Rbv
         OP6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xgo06j9ahnzor5Mr6mVoN2N31xaczjU8L11cr2e3IBE=;
        b=AQy/jaQZ9xm9tbBQ2itC9kFamhIsFnqToJwo2530q2yQL55c5jyNgV9HW40m9XcUsZ
         053RuIyxN385j405Qr4rhLN4gplDoxLS1q/jE5fVa3dy080SiR6RtTI2DRDY+E32R9Ji
         O8NtEzUnYJZtK6KD8XK6pxVxsEdk4WtWJLkZgLDTgMwC9vA+7XI56K1dqFb2HsQf1Nab
         v8/uckF9bh8S/JJblH3s74F6cCXtCdTgYauTzkF8wL9umYq+l7G0Do2NSHkUo1XIWvE2
         8rBD/5oG6ZSfR+gld30U/zgaEnC2iA3O3mP+9w8jmCb87wAcs1x5LbtN6gHMeMgvVAx+
         gAnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=i7htHyT0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id q59-20020a17090a754100b002340b20225asi32875pjk.1.2023.02.17.02.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 02:05:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id f11so437237pfj.11
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 02:05:12 -0800 (PST)
X-Received: by 2002:a65:6050:0:b0:4f1:1bbc:be70 with SMTP id
 a16-20020a656050000000b004f11bbcbe70mr687528pgp.6.1676628312200; Fri, 17 Feb
 2023 02:05:12 -0800 (PST)
MIME-Version: 1.0
References: <20230214015214.747873-1-pcc@google.com> <Y+vKyZQVeofdcX4V@arm.com>
 <CAMn1gO4mKL4od8_4+RH9T2C+6+-7=rsdLrSNpghsbMyoVExCjA@mail.gmail.com>
In-Reply-To: <CAMn1gO4mKL4od8_4+RH9T2C+6+-7=rsdLrSNpghsbMyoVExCjA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 11:05:01 +0100
Message-ID: <CA+fCnZeK4d7CvaHxCR0oUfZMXbh5-x9H3cL_8Rk9ZqnRryOqBw@mail.gmail.com>
Subject: Re: [PATCH] arm64: Reset KASAN tag in copy_highpage with HW tags only
To: Peter Collingbourne <pcc@google.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	=?UTF-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>, 
	linux-mm@kvack.org, =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, 
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com, 
	will@kernel.org, eugenis@google.com, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=i7htHyT0;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::432
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Feb 15, 2023 at 5:44 AM Peter Collingbourne <pcc@google.com> wrote:
>
> On Tue, Feb 14, 2023 at 9:54 AM Catalin Marinas <catalin.marinas@arm.com> wrote:
> >
> > On Mon, Feb 13, 2023 at 05:52:14PM -0800, Peter Collingbourne wrote:
> > > During page migration, the copy_highpage function is used to copy the
> > > page data to the target page. If the source page is a userspace page
> > > with MTE tags, the KASAN tag of the target page must have the match-all
> > > tag in order to avoid tag check faults during subsequent accesses to the
> > > page by the kernel. However, the target page may have been allocated in
> > > a number of ways, some of which will use the KASAN allocator and will
> > > therefore end up setting the KASAN tag to a non-match-all tag. Therefore,
> > > update the target page's KASAN tag to match the source page.
> > >
> > > We ended up unintentionally fixing this issue as a result of a bad
> > > merge conflict resolution between commit e059853d14ca ("arm64: mte:
> > > Fix/clarify the PG_mte_tagged semantics") and commit 20794545c146 ("arm64:
> > > kasan: Revert "arm64: mte: reset the page tag in page->flags""), which
> > > preserved a tag reset for PG_mte_tagged pages which was considered to be
> > > unnecessary at the time. Because SW tags KASAN uses separate tag storage,
> > > update the code to only reset the tags when HW tags KASAN is enabled.
> >
> > Does KASAN_SW_TAGS work together with MTE?
>
> Yes, it works fine. One of my usual kernel patch tests runs an
> MTE-utilizing userspace program under a kernel with KASAN_SW_TAGS.
>
> > In theory they should but I
> > wonder whether we have other places calling page_kasan_tag_reset()
> > without the kasan_hw_tags_enabled() check.
>
> It's unclear to me whether any of the other references are
> specifically related to KASAN_HW_TAGS or not. Because KASAN_SW_TAGS
> also uses all-ones as a match-all tag, I wouldn't expect calling
> page_kasan_tag_reset() to cause any problems aside from false
> negatives.

All the other page_kasan_tag_reset() are related to both SW and HW_TAGS.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeK4d7CvaHxCR0oUfZMXbh5-x9H3cL_8Rk9ZqnRryOqBw%40mail.gmail.com.
