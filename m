Return-Path: <kasan-dev+bncBDW2JDUY5AORBLHTSWPQMGQEJPYPMYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 09C8A6913C1
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 23:54:38 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id f12-20020ab03d0c000000b00686debaf70asf1396341uax.23
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 14:54:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675983277; cv=pass;
        d=google.com; s=arc-20160816;
        b=jhzAg3sZJcdrncBu1lSjzCCyxAK1a8n3E/G/KY4UvFp6/CaoZoCHIKP69TIcik2dc0
         oQPmiSw9DztKsKksyx8L85ZUwAl4Iff+/RmGVffxeJs5db/l0KB8k+vgot2TlRbEGSZO
         uGoZmXIPFsrOvNz3lCJfNmtRgZek2cc9Z8VEXwsGEA2QEW9FgNe2efY+eXV4duB2yLPM
         0mOtDuDhuuKwO6FDF68rQWJWZk5TIXZBuT5uqaBlofFWPFrIwCVofPBaHdpQopd8ExSM
         qgRPNLsLpshyb+uUMT64ppOXXhRHpPPlk1mo2LSim6Guv3ZUHQzG/cueJYzrG/kJgrHa
         7O7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+AcyXO6/Mv1xy0hhEplYXztLHol4Np12sN4MUNhRvfU=;
        b=PZJNaDcJ14IXUFU+CX6IlLSkSzfhNWwzROuP/du8sR7tvv9EJ8mFkfiJGQPlc+MRWE
         tOHeVw06SCFMVF3jt5VLAaH3pIA9htd6CnnBADQxiNnko896yMjYHdCJPPLjpOghKi3J
         tPLCFK5BelgBwSnPTkaXxnSsCcrGi4LWG5DP+UVdiEZV1vntjMzQxZj4cklNiMKvTXbz
         JogvICne1wWO8uwlrzDEpN9IO3MeiQRQp4IaO0ohu9d6TFAcBLhsIDziTMGoWxPpBEr8
         0HkOWdrX8r1Lite94xFoXmUTcPRZSafbQYoTV6l6rh9rBKM/9bjYh7MzGzj8v3c/IPnN
         iJOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="G/FznRNO";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+AcyXO6/Mv1xy0hhEplYXztLHol4Np12sN4MUNhRvfU=;
        b=fe6x5mpfdjQZ97FSvcJBf/BBORszvRnJwLlRPxKpz9IOEk/1hEH7FG202zT4N/ZGeX
         6RBm5s+XZkPHGDjmxqOScz4ip1mH9jtnddsz0SvtaVtkw18cddQyXvO4N/eZqZkb1UuO
         BY3GvCPHne9HMcVbiEvs3n3U7JpgTQPYmEzDOrESoiWzrqpnXtyZWpglXu06zsBaP9Aj
         WrIL8fErmVQtm81UKc+2RPFXQb/kO7R+7B2vS02dvoTb109lOrvUNTtcbTutbOSc9hZk
         8T30rYtAvWDoQoCvr5ey0qkv+O4dnQMLYueDCEKvRvKfU6uoDSpgZp7N+FXGlYJNBdi8
         1lIQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+AcyXO6/Mv1xy0hhEplYXztLHol4Np12sN4MUNhRvfU=;
        b=ouxyka964pVcD5kKcthsONYJaq1GRXbN2Ts0uY3F0Q2kYZvger1t0tJM6n7AW/SSGI
         VYTakD2XBAgKnBtj3Gp6magdrVNb3iqqZ3uRzrt4/6r+cV51iD3WUsNxDt9PERd8Ez8F
         IauNvS5m8a6jrw04nC7SODzO+GbSGAGAjs5KqgKhGqteeNNfDav4BwUK6uJYLaVH97UH
         0Xn6X45ISE2LuChtguoPMyOCjrQa6r7w0V6dPjpZ8emm34rBoKDPi/1IEX7XLfPkvmiJ
         wP4RZmxfIl6EzPQKI5eqrBHp6rLA4xJ81V5dJkOv12+i3PpCfMpgv8LoMdLIWatrRBCs
         U24Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=+AcyXO6/Mv1xy0hhEplYXztLHol4Np12sN4MUNhRvfU=;
        b=JySeW84MtN7ZebXGSC5HRhHDPHXoKOGTpe3HfD8DfPgy8VQqTxj9/T3gtVhCBl58kf
         QMPx2wD2EuA1tcvggVUuIdcFp1cQV8358RjGpgpyJa5o/3bmXkReCQ/xV1YqhdDg1acf
         /rGwUwJ6Aym3HziDddeXEvlM5iu0yiw7tAxUTUvadY7krdHlkU1w5DaAbjLjkcHDrEfp
         0HLqcj2P/3lDubhUX1f+yeQJVBe4MSgGyaeszAIj1a/Khsi+uYzL7ATw/dIcvFrhQWK8
         WaaemWoAi0hz1oZW8nJHtEJ/cXBfx8/TPBJZhh5k+QhCxEL6xod9n3QVA0mwLXJcbQ/f
         zNZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVh211eicZLEQ5UgEn/iP72inSiK4Ya+1z8SxpLVOxD5xxXlw83
	eEJBFk+jGRs9QQolyLwP5Hg=
X-Google-Smtp-Source: AK7set+bjqXKIjRfU6E+z3lzbjcFsqigWoxDNeoqbUs0nWd81uZSfd8XqBOA2HTzwhUxfN45Ymg38Q==
X-Received: by 2002:a67:ca1c:0:b0:3eb:36dc:3593 with SMTP id z28-20020a67ca1c000000b003eb36dc3593mr2745635vsk.78.1675983277042;
        Thu, 09 Feb 2023 14:54:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dc96:0:b0:411:bfdd:808d with SMTP id g22-20020a67dc96000000b00411bfdd808dls1268928vsk.6.-pod-prod-gmail;
 Thu, 09 Feb 2023 14:54:36 -0800 (PST)
X-Received: by 2002:a05:6102:c10:b0:3fa:58d8:220a with SMTP id x16-20020a0561020c1000b003fa58d8220amr11312485vss.35.1675983276303;
        Thu, 09 Feb 2023 14:54:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675983276; cv=none;
        d=google.com; s=arc-20160816;
        b=WhfNtH5FOYLBO3sbx/jXUJ2XDRqwrKyebZvbbEQfvzGDysIdq0HIT3GnAzO/qoXIw5
         D4qhKIs18JdiWE9TkHMm5DyBCqDdTRTPpRCoWL7yiRpGQ0eLocHskoANhcugmGX/cuzF
         Z4ZVzNpaRwEkq6OYMN54qGKYDVdTKDEQ3IaQx5SO6FCoQgWXCrSZbJKnYvctY89WuiFE
         Z0OvUnG6JHGfFZKZtslV/Q8GWDAGbSXvX7U5PLOGNjEjvD/pBghh9eepr1SpMY3Unfmr
         F+ADgiR2Ti9I3MaCb9P3fBrxyWAv+724rsXSnb6jaxAFrPkHizNyclmS0Rd82M36jvk1
         plPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jdJbx8cUbzo0up0IR5lEzRMt6aSIhKf92x7ZKJB7vEo=;
        b=vfqgy+4CgG4ZJeLlo7325Ea4EVV5KLRy7ksvbbSeWJuM0/2SsgXKV3j0bhxjOzqfUX
         agSH+FT1V2aPCW1kMdUgu9r7Gznmfqxzy5nvUDDhTyfOlI2mybuBN1/5IqKLH1bLqzWY
         +cTieeyBTJT5eG2HXhDftkRZRn2fh91jT4ee2cArmD/STCFK/6ENKNfvFBonwWPxSl2E
         +hymkch6x5uejDNxwGT1P9aIpiBK+1ayzL8HTo6AKaPSolSe827FBnLmU1GAkKsTOFzi
         g3dG09Vuk4V8nLW942eErhwl2UMiMySAlPMQMl4qiHlZJoYBl1yDJ1+J8zCkrQWtkKMw
         alsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="G/FznRNO";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id ay12-20020a056130030c00b0063914c44d3csi384672uab.1.2023.02.09.14.54.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 14:54:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id iz19so3246869plb.13
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 14:54:36 -0800 (PST)
X-Received: by 2002:a17:903:22c1:b0:196:6319:a029 with SMTP id
 y1-20020a17090322c100b001966319a029mr3302057plg.12.1675983275394; Thu, 09 Feb
 2023 14:54:35 -0800 (PST)
MIME-Version: 1.0
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com> <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
In-Reply-To: <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Feb 2023 23:54:24 +0100
Message-ID: <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
To: Dmitry Vyukov <dvyukov@google.com>, =?UTF-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>
Cc: =?UTF-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Weizhao Ouyang <o451686892@gmail.com>, 
	=?UTF-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="G/FznRNO";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633
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

On Thu, Feb 9, 2023 at 11:44 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
>  On Thu, 9 Feb 2023 at 10:19, =E8=A2=81=E5=B8=85(Shuai Yuan) <yuanshuai@z=
eku.com> wrote:
> >
> > Hi Dmitry Vyukov
> >
> > Thanks, I see that your means.
> >
> > Currently, report_suppressed() seem not work in Kasan-HW mode, it alway=
s return false.
> > Do you think should change the report_suppressed function?
> > I don't know why CONFIG_KASAN_HW_TAGS was blocked separately before.
>
> That logic was added by Andrey in:
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit=
/?id=3Dc068664c97c7cf
>
> Andrey, can we make report_enabled() check current->kasan_depth and
> remove report_suppressed()?

I decided to not use kasan_depth for HW_TAGS, as we can always use a
match-all tag to make "invalid" memory accesses.

I think we can fix the reporting code to do exactly that so that it
doesn't cause MTE faults.

Shuai, could you clarify, at which point due kasan_report_invalid_free
an MTE exception is raised in your tests?

> Then we can also remove the comment in kasan_report_invalid_free().
>
> It looks like kasan_disable_current() in kmemleak needs to affect
> HW_TAGS mode as well:
> https://elixir.bootlin.com/linux/v6.2-rc7/source/mm/kmemleak.c#L301

It uses kasan_reset_tag, so it should work properly with HW_TAGS.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg%40mail.gmai=
l.com.
