Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE5KQ2AAMGQEFOSZKSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C8A552F7C3C
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:13:55 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id z22sf3094253ljj.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:13:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610716435; cv=pass;
        d=google.com; s=arc-20160816;
        b=tLsyoYKv2EtZChYtqe3i7egGwRIVDSMAZNILhJ6HPsf4vpK2fDYvXUnOhVMeSo6k6R
         5d+USnYca1JyOs1ErNkQPf6ZHbo76QkMZ+BJc8Kye8GFaZEjlDCHmDFDzZuYHp5+TV91
         F0rWpaJXeUHzPry5V8ykfeOWdfmhxs7W5PTDpKJubKmNNFXGn/LBux0H3QQKITY+PXlw
         GeOKjScCuhBs+wWf8LgsrkBHDZfw578LE38+CL8ytvt8/QrmGZQVT7J7Otv/OKX2xb+j
         7Zuk7iSxfT9S1Vq0DVNvh/YihE1yOrZDR9x8uKl/JzZhgZE5odDlYWPz4txGvfdYbW0y
         r3RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=sHqyPDQIv7o+p7jjV7EnwS+bnctkYLZKjprUfnuJzos=;
        b=EXfKhCEEq0T0lsurZ1CBnUE90xMjStX8GB2vlELQqbRwrRfPGrFVYnAUiGcwll8aO6
         1zdlaeaG+WLyS2gmCdXeqf57NamhwSbLHl+gm7ne2sgGow18svNLdXtu9P6t9LwnRgTF
         2IKYZoNF0Oxd2s5CgW5LtuH0+uWKdEgXvaZEpj9//5diIXrlIMTBkCI2FcklZtDzIaE6
         i2Gr4gKmg2z6byiszy5JrUVOETFSO2bGx8VQp422mRx5Jfiqv2nCama0IHIEa/HbzdRF
         XReWJWBcaqrZJVacjBIvmp6jhqHEY2TagKotLT2/mrpz/Q+I47yM3XAKzOn/gsO0pNHv
         F5ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NJnjEoGt;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sHqyPDQIv7o+p7jjV7EnwS+bnctkYLZKjprUfnuJzos=;
        b=JvvoxOZntOT7hE9eF+drvrY5k1yUMc0l1uWbPFmN0lPS+tqNY2DpbuNkT8JNlzSgss
         jG7sQSlGomfBgqyyIFcInyM91FJBeqf/g9nisA+mj/rz4TcRub/8XU6o43EAEepuAJjG
         CSiOpVmE+CPYqWROI9JFN+G1alpfUY2jIkL1/HZil1CMbLn60ZAIDOYjVna1cQnBxaMg
         8RVoYzPRI6FUxiB1BhhTeKqpLN6zfHI0lLvjBGMczqDpNVBTSf4PTZ/QPrny2uXOu27f
         +VMEQTE+D+Dl62Au7v6GronoKRO48Fp2LEK/u1m6lCkpi1fNHB12RgMGKwWy/2+VS6Qc
         F5hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sHqyPDQIv7o+p7jjV7EnwS+bnctkYLZKjprUfnuJzos=;
        b=bbKyPoN+1lbFnyzuPnPss9NL5xGMKXh5NrRLvlrZ/k1KYndf9gL+nQZMN3PYrfKMrK
         Y2Mnlk+xNEHvS5H4gR8Yk+uyIVe85OZZQUMfdh+a9534/maWUHaiASY/JZq2Ryg4APsK
         kIfRcXrvEkr6U8Q3Aq2DnLRPwJEc2ANwY+c2h3sbcg12S5bNA9qWRP7QLDA4SFniOD6G
         xEkfoMOU7OpB22A0hvtzi0sCVYJ8HaGaWFHGRO/6nHpEcZnxN6RiYLfeY4JAjusNLvjN
         OpxDPq4HkjgnNAIpMKDvmOTO/yKfDsHDdG0rv82OVc569O3tyTHsuGbtnmw2uhTylt/9
         sgYA==
X-Gm-Message-State: AOAM530QrpLQqh1L8SCuq/r1XPMmsdDE/o2LeqrpnX26bbbkgj5BCD82
	xP5GLJXb0PYuO/RFyvhfpdU=
X-Google-Smtp-Source: ABdhPJyLG0OwhC5B20x8rPD6HsBsZYH5VevHPo0l9rEDkNIEpKNSTG6qcC8a1cSK/t5k7iMdRljCJw==
X-Received: by 2002:a2e:89ce:: with SMTP id c14mr5040560ljk.483.1610716435374;
        Fri, 15 Jan 2021 05:13:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3001:: with SMTP id w1ls1548771ljw.3.gmail; Fri, 15 Jan
 2021 05:13:54 -0800 (PST)
X-Received: by 2002:a2e:9a84:: with SMTP id p4mr5013924lji.160.1610716434045;
        Fri, 15 Jan 2021 05:13:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610716434; cv=none;
        d=google.com; s=arc-20160816;
        b=UOuOEsgIdB02ZV6Hk2wClEM0L3QCK0O+IUGyIcEjm6J2opEvWa501yNOJdoWJat9rb
         jmNBTCXQZb62O508f/guM2uPrHsqEme7XzJcvTk7xiZcWx3XzIWRTfZ2Cknyn1HhqG2Q
         N+MZKpIr8VLyTKL3M1yJJFMzkmCgIlWVWb0Tb++g89KSYldPmSJMD4swV2f1ffCo6TNE
         dhveHxMe4kNt0H0vCFESWW9gf9uSKDT3XaSUmZIKVz2JwLRSpZHIudeVdrouCX2/72Rn
         fGUSzXIhumqptREqGCo0bImEIzseh6C8WtNxsPjvUUW3Idj4Pk9GB1j82uYl3dyLgoRO
         FJCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=2g4u3xNSMK8ghZXqKFL1R16HFSl2YerHraRE1h1ytpo=;
        b=ZrOEC8Eo0bi3wMi7/OYBaS0rKqnPgadi9gHzGv+DPZA9H8/X91bqlunxmOZJTyhfFc
         O4IZGRFK752s3v++uQwms0FzIFtb6zK+bdzACcjTbw43qOA3pgtS+nx1A72Qr1Eu+QeT
         6mUUC04f4JL0Y2HluDequdftAkO7E7vC6oka/SSpPLUbLtP/FjkNIq4fTIKLNoQOeBD+
         7ei0/wNPhX4+MGvxGW/NGaxNOBcUEGfw4UpoHCjYqOdqYQdf3fjGoJke3n4dP2BGaD2t
         cNQs0IMmqie7csW9tnHYmrGCmTua/8r6mqHxmuJSVcwPPJYg5Jrilk3E7Dmaeiu7fZbJ
         b/mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NJnjEoGt;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id l8si336073ljc.2.2021.01.15.05.13.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:13:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id m187so1054240wme.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:13:54 -0800 (PST)
X-Received: by 2002:a1c:9acb:: with SMTP id c194mr8510839wme.43.1610716433539;
        Fri, 15 Jan 2021 05:13:53 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id x17sm14605648wro.40.2021.01.15.05.13.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jan 2021 05:13:52 -0800 (PST)
Date: Fri, 15 Jan 2021 14:13:47 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 15/15] kasan: don't run tests when KASAN is not enabled
Message-ID: <YAGVCxWTBlv4ZITG@elver.google.com>
References: <cover.1610652890.git.andreyknvl@google.com>
 <da60f1848b42dd04a4977e156715c8d0382a1ecd.1610652890.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <da60f1848b42dd04a4977e156715c8d0382a1ecd.1610652890.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NJnjEoGt;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as
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

On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> Don't run KASAN tests when it's disabled with kasan.mode=off to avoid
> corrupting kernel memory.
> 
> Link: https://linux-review.googlesource.com/id/I6447af436a69a94bfc35477f6bf4e2122948355e
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 5 +++++
>  1 file changed, 5 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index a96376aa7293..6238b56127f8 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -47,6 +47,11 @@ static bool multishot;
>   */
>  static int kasan_test_init(struct kunit *test)
>  {
> +	if (!kasan_enabled()) {
> +		kunit_err(test, "can't run KASAN tests with KASAN disabled");
> +		return -1;
> +	}
> +
>  	multishot = kasan_save_enable_multi_shot();
>  	hw_set_tagging_report_once(false);
>  	return 0;
> -- 
> 2.30.0.284.gd98b1dd5eaa7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YAGVCxWTBlv4ZITG%40elver.google.com.
