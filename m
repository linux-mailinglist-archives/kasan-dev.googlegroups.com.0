Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYPYY2SAMGQE3M62EBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D1E5736F14
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 16:49:07 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2b46d6a2e75sf20531511fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 07:49:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687272547; cv=pass;
        d=google.com; s=arc-20160816;
        b=J/u4oNvJu4xlt/3Z/VJawGACrC5oNqDFpi1eZvrza8Ee0bHZ2uMeK2hfffTWGqPCle
         wnoqeIqAIBIyXP45Qi3vxdlZdKlZWd+MkZVqXjTdNUsQtf4UoPJIvugFR5Dv4QM1dskL
         vxW7GBp/N/J/u50ulfdaH+U4gyd4DN10yZd/luNkHSMAV07PurKZJmTW0W3ThwItBRTs
         8zzj3zllIBggQLGwpfVR/OppJauJpp5U2NXomoyqUWyU60Bxfs+w9k/kT6Oy/rjpS0Jr
         AUvHPfVNyn3wMGnBPLArFMnvA1FiGrxQlwHxo2Hi2TNxQZL80nXY9szWf2/P/Nx8t9Iz
         CrWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lut8g/VnhGgCBfCU1wnF84UNfKISyg8eoNqD6nCt+sA=;
        b=db7ZtGrW5XwUlegBCWz/cO8Ln8Sg6lWRkPAOiFfKuxSDfuMltgbb21TndcRHpN2/2Z
         EtjfSfjGqQXSKV8rrLP4t88dsfiaYMyNuEC/RCv4CfxNZ/ReCHvuVSDkJ5Tk6H/c4bLy
         lnTKDHteYdHCqXWASs2gkEpe6eishWdXx6jPIqIswh/PL8Hk6SnTYT9iZj++HO4iAyCh
         Nk1AflVnoDqiD8gCvMi3vPkY5OsDZjZcO7tG6Jv6HPGR2/2QNpZ2V+N6U8ZM/KNxFmN+
         HhETDuTfzq3+ugyTPFP/Z0XW3vD6cK9KnfvFOmxTrlAHhmuqNfg233yEx//axUNyP1ka
         Qz4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="u/nNunrJ";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687272547; x=1689864547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lut8g/VnhGgCBfCU1wnF84UNfKISyg8eoNqD6nCt+sA=;
        b=aPLp2f4l3qc7qsveEsRV/in0tKB5y7y8OtdOtyihwD5T3ianIgmGMDin7UemUqmc8D
         oSqSkFbPLxy6NLGZere5AZZX2Pbba2QZSWdexSsdujBuO/4R/SBkn8HyDnr4jD2De9YS
         Qm0VBBE38c0xXQWg2ZWdoPQtwCjdfMqk5jRzg9SmLIwep9p4ArZEbJTqYZmBHcY1Of8g
         AnU+NDW8mRSLbWilt6tmBpPESy2zaIUa1rkIbBY+H+8e273Us8Q/zQYy6TtzgTbg3uA/
         qmU6YvuhXpDrnFq1AsLE7JvNCFGhg+uG1e57p1Huth0f0cMPlsxnyeJi/KrdgTFWGg79
         uskA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687272547; x=1689864547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lut8g/VnhGgCBfCU1wnF84UNfKISyg8eoNqD6nCt+sA=;
        b=SPuj9fiPxqCfHjgMZqy+l+yU1IuXMTrpiljl/1nUH+ZliA2cjSDQ9ndkD65F9bQtQh
         3yjumT70rpWbyXsZ7Jv2g+x2VegazknXwR3UsO6e5Nf4JO57JAZanuE8xW0V7qdZtnVc
         k4uic8j2tmtYzYMu+yxgRy0/vYYfg2exbfnWJThOylKa+uGhd5Z+TKm2XxpNBkVXu+7K
         tN1ZF0Swt0OBRGL/WA7Y/iOCQlgj0Mesh5h9bokTKJq+qQ2sksvjhyL4x98fCQlhAqt2
         dSP38zUeKCdPNRw29J7g6Qn6RMG8tYDdOwqnczzmibHAeSOtz+U5ljsQXpDWych4sce0
         3rOw==
X-Gm-Message-State: AC+VfDzOat2z4tODjGvJKh1zYIW19QGpEAj3jUP6akZ/6R1VSUf9WWnS
	q14VfB6TaiJ0ATtDzumNx2Q=
X-Google-Smtp-Source: ACHHUZ4ID0OEGAjc8QqJAy1NguhFp9EeMxvhTyRNshCAKIM4sqGRjLw2bobRyDBe8c9lxeS9xSRuAA==
X-Received: by 2002:a19:e30d:0:b0:4f7:6762:cd1d with SMTP id a13-20020a19e30d000000b004f76762cd1dmr8407864lfh.51.1687272546152;
        Tue, 20 Jun 2023 07:49:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:608:b0:4f9:5593:b2ce with SMTP id
 b8-20020a056512060800b004f95593b2cels152555lfe.2.-pod-prod-01-eu; Tue, 20 Jun
 2023 07:49:04 -0700 (PDT)
X-Received: by 2002:a05:6512:32a8:b0:4f8:673c:3f26 with SMTP id q8-20020a05651232a800b004f8673c3f26mr4485552lfe.68.1687272544353;
        Tue, 20 Jun 2023 07:49:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687272544; cv=none;
        d=google.com; s=arc-20160816;
        b=RNlzIQdClsf5+FJA3qWU+ywcPyrjPR9OcVBR8ObWUshe0z6U+f61uoP54r1Fz9Hr3r
         4Z1gUS7xvmf/lbV8fy7feoNFd2bZDX6S366LWDNvVvEX8uSAAPqZ8kaGryfwncGedywm
         YEj98aPxsHEAccySt5q1QQtVUydt5j1DwWs5TF4MqTpO00MVQqPHOCvg/Dzvm7sNYvfb
         +VuulJaJAJzycnzsd3MAShz4ycPqq8c0Wb9ST7Kd7O2iy4qtxsdB/YEy5qrHS0HTqNDP
         DQiGKgzkR1MkJmw8ifwpUHujZw4g8mWGIepWNe4p8YPBSo3VNd83VQoyLba8nMC6w1jK
         w5Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tFBJCFv89ibLGDxP64+KT5RKVRcJ4ABThqZOUh/7S8U=;
        b=qbh0nG1wWtnMy+GR9o0a7+y9bP6RU7HPT70hkm4DGz1IUUk8nY/6DFq3kMVLQarQ+7
         gJgEpWLY+nDoYPLZbGpGTTwt8J5tPioFKTpsNswitizrWEyheOz6VMYkttLvDdrhvFdq
         yNijGT+Z0qJy9panb9OANKk0rnYt6i1pXfKxvj2YAgmkLIEzg007qt0KH/SGDCcu1Ont
         +rpPpTLp1zVPO8Y/mCgTLs+HhnVPSCs3TwarnMjjk2dRvvBR0aenWtrK7306yG8GQr4c
         Y2a5Va/FTnO0E7wDe1CAAl70qI0tUTrYjr+++U7IV2c3QqJiEn+IjPum1cEcylbbc8P3
         8Ryw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="u/nNunrJ";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id y17-20020a199151000000b004f8424a570esi193694lfj.12.2023.06.20.07.49.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 07:49:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-3f90b4ac529so33013995e9.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 07:49:04 -0700 (PDT)
X-Received: by 2002:a05:600c:231a:b0:3f9:b430:199b with SMTP id 26-20020a05600c231a00b003f9b430199bmr3194468wmo.15.1687272543652;
        Tue, 20 Jun 2023 07:49:03 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:8530:a6a3:373f:683c])
        by smtp.gmail.com with ESMTPSA id i2-20020a05600c290200b003f42d8dd7d1sm13668387wmd.7.2023.06.20.07.49.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jun 2023 07:49:03 -0700 (PDT)
Date: Tue, 20 Jun 2023 16:48:58 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Taras Madan <tarasmadan@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
Message-ID: <ZJG8WiamZvEJJKUc@elver.google.com>
References: <20230614095158.1133673-1-elver@google.com>
 <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
 <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
 <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com>
 <ZJGSqdDQPs0sRQTb@elver.google.com>
 <CA+fCnZdZ0=kKN6hE_OF7jV_r_FjTh3FZtkGHBD57ZfqCXStKHg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdZ0=kKN6hE_OF7jV_r_FjTh3FZtkGHBD57ZfqCXStKHg@mail.gmail.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="u/nNunrJ";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Tue, Jun 20, 2023 at 03:56PM +0200, Andrey Konovalov wrote:
...
> Could you move this to the section that describes the kasan.fault
> flag? This seems more consistent.

Like this?


diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 7f37a46af574..f4acf9c2e90f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -110,7 +110,9 @@ parameter can be used to control panic and reporting behaviour:
 - ``kasan.fault=report``, ``=panic``, or ``=panic_on_write`` controls whether
   to only print a KASAN report, panic the kernel, or panic the kernel on
   invalid writes only (default: ``report``). The panic happens even if
-  ``kasan_multi_shot`` is enabled.
+  ``kasan_multi_shot`` is enabled. Note that when using asynchronous mode of
+  Hardware Tag-Based KASAN, ``kasan.fault=panic_on_write`` always panics on
+  asynchronously checked accesses (including reads).
 
 Software and Hardware Tag-Based KASAN modes (see the section about various
 modes below) support altering stack trace collection behavior:

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZJG8WiamZvEJJKUc%40elver.google.com.
