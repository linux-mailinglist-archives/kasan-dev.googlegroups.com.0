Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5MUSP5QKGQEZYZYVMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EC8F270041
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 16:55:50 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id p20sf1550547wmg.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 07:55:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600440950; cv=pass;
        d=google.com; s=arc-20160816;
        b=xOfhgaUIlRLpWllt2dnJAVGRCYWvEfKpKWvR0F+QabRILiQsGSck/rID+ROOMBz5MW
         oiqf9wXewBIt2KFIaPTcvqq6HPWJF5kOOT3a+cMASraoXvzflUH1hOgTEvt0XMQCZu8v
         lJMETtns7V06zPdkNSMlC0Kq9RABI5Aw9H41bKh61f+38H9JC7xy0zi0T4b2w0WbtHt0
         uN0CzmlmCrfHlfePYGazJt7/NOdH04ve7GgL/EvqimWbBae9Z+M4H/dAhlVaH1loezg2
         /DUWJ0Y0GBuQIM/RNJr3Z2fIKI0PAyhVfMH3Z6a0Pkoz9fcblRfFT+Sq/e/eMHpWePMQ
         bv+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9rBe9+OWliZYy9DxKHHgBe7Uej7Jf16lXZ7nI4socBk=;
        b=R6DaZR31jBCOoz38AuwpYwvcN9d/9BT4ZzvowVfNjj+j13oTL195GgAzuOzvGthNDI
         6w+bHHNiVIcOvRr2wx6xshoGdqeRWhJaP8N9MZNE/coaHoDlxy06QlhZKi/r1NiNe5id
         DIF8psq07pcGf6qT5QC3qOkBt9KRGzZBGkCBgFCHjtCXtCpbiMBJW8PvmTMtkWwc4QKJ
         j9u2jspGh71jclQZj40x65KiP/SLT2SW2KEf/bmLfRT3YOOyFsmwEy/ydAqlfeMaFZ6q
         5UTuMXn2C1LKKVhxzA+clhsBQPfM6FTHmB3qIfs7FD2eoE+zUYTiCenAE32DKxG4y1N/
         OwYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hRpHFUiC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9rBe9+OWliZYy9DxKHHgBe7Uej7Jf16lXZ7nI4socBk=;
        b=chMMnvSHOgw91nyK30aC62JHUGiFT98GjEGtfzTox6hYeuBPGRrYplYDRBuwJgy12L
         4fav3tVBWugXdPvmSlodf/GHVDVarZXuyBhef5R02KayCeBpSNWc6SnbkFbV5Prpy+Qn
         Pwqjo7X6H5DIJur1Saqyu2E4Y1qdxKeywbqIuMDYK/9zQQFQtO8YJtkmVHIjqPGZWIdS
         WLsFFT6YP7AtqKk2TnHGrSoEq8NGdN6+hGFRI7qrTKHqDXi71hvXR1bcPek4LrG/Booj
         ZqYdopjubp0mCTGDAlSbaqAiecgsTLG66Opo/rFBj7tp/MfDFPxT3pJgtY3pJd/MrT+W
         M9lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9rBe9+OWliZYy9DxKHHgBe7Uej7Jf16lXZ7nI4socBk=;
        b=fE9n0mJ2hsBBXzZeLCQHrNRAShLGGsgxSSiaLL0UV9huRaFd14yYmQMMei02TiyOZs
         3fbjeZkgmTrROjHl7ABlh5s58UXye4vCk8xwJaWO29y8Ge+s4ouV6H+C3SW5aI9Frd+c
         SzBZkvuhhkC3PTdIZzaekP1fMyDIBInbz7np9S1QfjQID4eVvvpkM5X6F0ER5VUIuRh1
         4ceJN+zI1mkXwDNX5zIOPBc7xxoDZGrCY/3yov68etA0Zr0MOhhKP6ciGVznI8XNWz4r
         6BPzNI0rc8Z3xwQaKEerZkEP4MK7pe4AUaw4vvrqa6V3dRMNuCIC4fNZ70WXBEqHb0gs
         fB9w==
X-Gm-Message-State: AOAM530G3UjgqM3f1ukg+36kRMyxCxemsv1kt7I2pR5xr8dglk4oa1EH
	95P9OwPzYqq8ofxLwqHO9fc=
X-Google-Smtp-Source: ABdhPJwAhZcPisx9yZxOsSYP+azTGzn2zVCse3aWsis8N3VY3xLDm1R99hI8Fvoisupz1g/1x/AJyA==
X-Received: by 2002:a7b:ce86:: with SMTP id q6mr16850493wmj.163.1600440949889;
        Fri, 18 Sep 2020 07:55:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls7026792wrq.0.gmail; Fri, 18 Sep
 2020 07:55:48 -0700 (PDT)
X-Received: by 2002:a5d:4e8c:: with SMTP id e12mr40309937wru.180.1600440948819;
        Fri, 18 Sep 2020 07:55:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600440948; cv=none;
        d=google.com; s=arc-20160816;
        b=YQ6CyiVKUwArTXHoCiodWcKrK/ECYtjWj7aNq8SnDwEbIy6zP8UCOyyZ1Wm5+6FT1F
         KvNxeiOuTHbblVxi+afKnaBlUY5an0Ny2GMth6aOzJzLJHpBORZNYgWcojcrJ19pU1GC
         xEw5HpIOUegTwwPB0OZCS8D08TeM2+9OcXltLFjJumFtc4b5CLXo8PggW1erF7kQKmZA
         rRZxgmScNSHjVl2qRqQgtE4IqThCUbqjrQ5PkUKr9xbXroAsHb9tWSjNXy2dB28xXfxZ
         vAewnxT4Je20gzTDbkn89yXrqs3IIfEIB7rYB50e1zh4X1Zi9ymtaSTCJTAIy6VHA6Hz
         SAzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=z3dW688qENJW8v47iZvvhvhPKK/yGjEUH8Eu+wx3dcI=;
        b=YCoh5gmHr7Y6gSMPZlFvQfg0Gxs1WOtRJYukmQ/Lg1a5UDfmJDYxZ8jKJnPo4WEbW/
         JENcbxd9rmDiMXYIADAKcwioYa/ehP10/WsoPn+uZFSWyIujeqQyHnOLTO/gLtAOEiDq
         c3EKeyVnOj1WEalHjV1wdGJ9PxQ2Sh44d8f3V75kSaQGQhqyCcZ7iWHofFhy2qBm4SQO
         X2j4Cxw83L9EqmQ0R8wrhvCIJcZvhXi6v5HF3dyA9+4gh+WCTodsH7JZ1I3Op2AssdG+
         +aVD2vy3wTmuaB8MecpS1awqnMgOG0iTN+T0u9twU5b1lAbxp4LN7dsg8zeoZskHuwE7
         GKEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hRpHFUiC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id z62si87071wmb.0.2020.09.18.07.55.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 07:55:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id z1so5954836wrt.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 07:55:48 -0700 (PDT)
X-Received: by 2002:adf:f50a:: with SMTP id q10mr37861563wro.319.1600440948316;
        Fri, 18 Sep 2020 07:55:48 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id n4sm5659779wrp.61.2020.09.18.07.55.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 07:55:47 -0700 (PDT)
Date: Fri, 18 Sep 2020 16:55:41 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 03/35] kasan: shadow declarations only for software modes
Message-ID: <20200918145541.GA2458536@elver.google.com>
References: <cover.1597425745.git.andreyknvl@google.com>
 <272b331db9919432cd6467a0bd5ce73ffc46fc97.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <272b331db9919432cd6467a0bd5ce73ffc46fc97.1597425745.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hRpHFUiC;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
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

On Fri, Aug 14, 2020 at 07:26PM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> Group shadow-related KASAN function declarations and only define them
> for the two existing software modes.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/kasan.h | 44 ++++++++++++++++++++++++++-----------------
>  1 file changed, 27 insertions(+), 17 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index bd5b4965a269..44a9aae44138 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
[...]
> +static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> +{
> +	return 0;
> +}
> +static inline void kasan_remove_zero_shadow(void *start,
> +					unsigned long size)
> +{}

Readability suggestion (latest checkpatch.pl allows up to 100 cols):

-static inline void kasan_remove_zero_shadow(void *start,
-					unsigned long size)
-{}
+static inline void kasan_remove_zero_shadow(void *start, unsigned long size) {}

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918145541.GA2458536%40elver.google.com.
