Return-Path: <kasan-dev+bncBCF5XGNWYQBRB36FVKXAMGQEXRO7MXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C242C8521E0
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 00:00:00 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-598dfff24f9sf4798090eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 15:00:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707778799; cv=pass;
        d=google.com; s=arc-20160816;
        b=S4G94+C4cxf7ix1w0cjQB9fR4Hpv8m7BcJdbUWuS4n9hnpCorTEPGwS0WEokee6tem
         ytAKao7vw2KHdJwj0awSubKKMrbhWaMAhYCkj5aMvICszU9DbgYkweAJilOnBPSzls9/
         kw/4PskcDasaeLSLok5qo3Zqk1ezI5Qejmwz6/1ElFBARZXkH7IWxtY65d3hREwXKonI
         /J/Co2qZG1UCHFQNZjtSE9czqUhK/7pMgpocVTwlJCqi+lptMa4tCW9h7KEBYHAtFnKN
         dKjsURZCFeN05cOM79uiI7KlcQSK4NvgZ7aOOeORlrL8Ior5FWYaUkuCZeVByO8d+X2q
         vlGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IA/Yf0EudSbnTGqSTMtv6M5BUn5TmBYenHDf2IIe7iI=;
        fh=7yU6w58D1izvlhO5ZMmQB0FTQSVB26nrGDUcvCwOAR0=;
        b=cCPoreE9sLFrPXT57TEjXNZdln6IpGM/vrlmONkzBV2EBPVncXRrh4yLKcR5Z6LNAM
         BpAS8Q97gjFz/U2v1gfo68Sl7BFn26EDU0KtXX6XrNB9tE7U+sMZowSX2mL3MMVNI1UW
         lThLsJBMeeVF2+xizEetGQv/IPNtLaStCHVsfuJVs8JqjH1SwgzvZ26vZqqi2J6ogXw1
         WBDDSr8V0tvjwNiGZmX0f5zJr901AhK1Cy61ZMTZQpVYK9c0OZXcz1TRyOMgHt6MbR9y
         WNPVkONOxzw3hKE4A0pZuAAeLTXwBIxXcr4sGg+5YLAh8+PBWeYMXthpUH7Fkw3ykioX
         e0+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=RDzV1lZt;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707778799; x=1708383599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IA/Yf0EudSbnTGqSTMtv6M5BUn5TmBYenHDf2IIe7iI=;
        b=AVt/WOnSCoJHuggT4LcpDIjAGLeXtdzvM4MoockNXmV9XbAIkGPiXyGzXCvKSIGLVT
         A1qFfQtF1waOrR7KzCmr7A1Eff96Zvx3hT4rHuJy9D8DGCNKjYqJtthtLQVMm0DAFSM7
         zTYClrlbrSkaRgRA5dUZPsa/YLb+UfYHaR3ty+Dp3ASigaedvmPH2LJMJiRBhrrbBg/A
         mHKjEDIplVdH1yRvt6RzBUkDfWRA+JwwzWh+GOpiaRAhYgRkwJ5XvLU/WNcz6L1dvJ4q
         PZ+a3u++jBqARQj/3hvSxZZiBs0WdT2DB8ypRppfgdnujAXmDfvWGFmhslOdxFHN7zun
         1PBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707778799; x=1708383599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IA/Yf0EudSbnTGqSTMtv6M5BUn5TmBYenHDf2IIe7iI=;
        b=Mp57f6KMPOD8IgxqtgpyTfmEcK8x0QP5v5r4LRRextxiiEwywD26V7nQPivbV2bQGd
         nsog4fw/dI5/rpPXTeP5coxzanuVBYEpCnhV/ZIokV7txdSL0tr5ai/dmvfgJjT+I5dC
         RnHmjCMaPNXO/loSCFfWbVqGhi6lOAWAJgVxHhyFn+o11nbDzyrKdysDuiL1SQLJAXsO
         5u+QZkOdQ6qyBVgYrrwYW1zwZtrn/jc9CZWK0YWJZv7kn1bqiNFe8ERhhn70vzU8ngUI
         hsta7sDtwDze34fYzFuKucycC+kZNOvG8mndxMZ/tmRdQpFErCCIqaEAh/22jKfQR389
         xNfA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXuX0SQmaSG36s8a0DEz1olJBNR/SBfDRCj9VVrtD6hpQqmAHVIfl97dpeVY0JZD1B8U90elgGz+h2EiQf8LyOK21tvPCsABQ==
X-Gm-Message-State: AOJu0Yx0vIW0eFFzbdIs2YciLUzRYTsDZaTrIetLTWSk7FtUi+t2/e8h
	lOOSVqb3YtzEi9/c27RVHptAI273Uknl9Gg9He0CBgSe4H50O3Vr
X-Google-Smtp-Source: AGHT+IEC6cAHZf/bFh25/3i1YcuELR/5mLbW/BrxYsAhFehrzB3BrYs23UMYy6FtRB/gRzvchBDI1w==
X-Received: by 2002:a05:6358:999e:b0:179:1f8b:445a with SMTP id j30-20020a056358999e00b001791f8b445amr10078945rwb.22.1707778799628;
        Mon, 12 Feb 2024 14:59:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:510b:b0:297:2864:3177 with SMTP id
 sc11-20020a17090b510b00b0029728643177ls513081pjb.0.-pod-prod-09-us; Mon, 12
 Feb 2024 14:59:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXrBqHUMsuIR04ynNsc80Sa4eMBRyDQhVB7qgEKJCwadeqf0ghHnYRmcmDEeefIaGXUlWgljeyojLyhaRim8SA3m8L8bmCtEh5H9A==
X-Received: by 2002:a17:90a:8047:b0:296:940d:281f with SMTP id e7-20020a17090a804700b00296940d281fmr5215585pjw.22.1707778798567;
        Mon, 12 Feb 2024 14:59:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707778798; cv=none;
        d=google.com; s=arc-20160816;
        b=nb9rb9GcxNp85/wDTRdLuNOXLPodshjF28RDkdQ+/OpyssTTxlyB6u8J5lctUpDxFW
         Ht+VRNC9SIDdpgE9tl8WmeMKpZ01yfMLLvtlKMT/RZ7ypdMjZwDo3yVombQMveV2q3VD
         WFUEgpvNm4DrwtNypmkP4vYeDeU4bpwpufNzFtxyOME5rEQMJCNqrz5uaMwDJC7zUDgi
         dZbij3rxMe9qfDHDxtGjAGq+tiMxlQZsHtVZnrQjO5DAU/r26tQKMW14CFetaOzIT9zc
         3umHXYpkLsHG50i74RtJEBmdQFLuZjK0++R3cMdhtCUm6B3vW5Ljca7gzQcclDEvP/7m
         +YCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=y6AxC+gFNzLegoAwuSB5/O4MPPTQdLkk2fG8bSEFU8c=;
        fh=chaEljHufMgtm8HXiUBdhLd+4lWlCPSJtmv4rNZ4p/E=;
        b=j1fTpd4tgpfRGCj4/BMBwXQ1L//YhylN/RwvCA4ArUyDFMs8zAw1VSNUJA6KuzEWza
         BKUWOiiXw9NTkzFujVehoysa/MMfXxKJHN6xckoNyiq/uSqnXtuyOM14sX7bD7zPDqm7
         f9a0jr/Wf/+IGh557Izm3Mri3uJSaHC4A3g8uy2KO2OiFThLEpMmHwborf2SPQIrpZFb
         AjfxZOR+OnovUqlG6ycOu9QAb5KlWXGU5Ejt8GzyjbJHsNCMBc6svXb+9Bx04fja/OTi
         /f5NDSspqw8Wric3Sl8N8hhVro467ZoPA9C5Bj9GZiUyUQXZXcpS6nle0hnVE1XmY9ew
         B2zA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=RDzV1lZt;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCU6+L/nuVz6jo1KulTBPwF3tLT/8a7d7/RG3qU0Fpa8dprG9E6JKd0HPnxXc6oTwWr746N749Jme3BJt6oducu0Rt7e06MwzmDyaA==
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id c6-20020a17090a8d0600b0029673bfedcfsi135258pjo.3.2024.02.12.14.59.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:59:58 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-1d98fc5ebceso17737045ad.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:59:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXZWWNK/M83g+0a6fxD/bgkPCB95jzunt+BXgYGD6iCVskw0v1gA90D9asWZ46sAn1Zyj5dyZ5FprF6QzSgO2/7OTLsHoKwrAxmJA==
X-Received: by 2002:a17:902:b90a:b0:1da:1d3d:7978 with SMTP id bf10-20020a170902b90a00b001da1d3d7978mr6422992plb.34.1707778798245;
        Mon, 12 Feb 2024 14:59:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVROAOiQtItqQunxEgINTavrntNtXTZaslgmHfG5Q7RlwnXTvT9TT1eaCN0H5wZM+ct2RsBbD3ZDH+NC8rq7n+JjfAes22TuhwSuygZM89XKuD7BkP682W5q9ycElWt5VGlJReqai9mCMH9xQq+QhZA58E+HCdgjw7Kd1+gXEfSAveAXGwhcVAOH3xBAsANb329dyHBD+eaeLXs6rSoVLewpamL6SHOuGfUVrCRPYjHN9Q3MCSxS+SSvRcDyrteoK8Ywupv6agfXGOm+1QauLmtgVp1iE/I4cU3o+6C1Hl7HgT8G2bpiuff6pA+5q8kasPL0BLlkuFkaD3kD6g1thGBwRhh0tvk11b/dpDcFGGEq2NMU5nUqe3InKk8/onjP8bOkI6Lb1o4632QK8xTgKXo5qgLIr7AHavi/rWRTSkfvkrcuLWdaR5Q4dbh7wJumbFzV80uU6hV5AWzay9MDeOIvCiUNEaDYIUF2VukCWA9zdvbbwoYmMZIwjUOAatXKPGPa2IlGMkmDjgXi61+LCza9yD8FP/hGhunMgVxVcN0Dpfolmzs82LDhk9CaLPj/U53YNUpcvmPUlawbkB0J12mFPBpgCHHhe6sRyExMMQYCic/a+ua/e4nDQL8RJMD8XnbAQItndtloTfPw3GLZv0JWupGRjdLnihttG88vOg7IU4LL01fC3k+9Em8wPg4MERa/RNBxGNFebsXE+aTr2AGlJC1/B+ETdhfn7X0lapJGqPHGdsrNfEQS4Lso9Zaaf/PNl21QKCrruv22TSb1UYnc+FJxpSKXTuc82S/otdsd/5JRXtwGIO8Q3WabYydfv73oCdv3jFpDLF+o5I5f0jCAfIA/DjUX5FBUDa1gKah2wJz8jglTuzFlXCe7pxe83RpR27ubUS8tHG14GGYOsAilE+W1tA9bjSzroFUCWr/I8iIkH+tjpgJ2Tw2HzW3JuDDSJ
 tuB/V9kuJKjqkJ5H2kgH8LvqN6M6o4lekz6PSp/epAevORPQOTWtMSG/3PsxPlx7QGDPRs04eIAjipf5LIwUrAqBYVE251nJxNY1aB/AesHY43bQKVFs1qGNBU036ITeeLZUug5cOG0FXLmKLdB3/fH8o44NvhWPF2AtYRw5QW9Zh9Xz7njX4JQcXRbnOCcH/bAUm57Fgq5MI+57OmdtFxen+vnXIqzcnMenHfFpZT13gDxizHq61b0+AJFVSSvzzv3i0iBy67NoOPjgRb8YdBDyAufAM1uiLkSgsRlQD28E5fDnXRqYrqtXoU/OIbTD+1we3GHNEBREvbrTxhXUj96MnEaGFwBD/PRNGasb79NNHllLa92Qh6lVm5OkxhlTWgR7CjhNJhoLZtiGserg+H58VXamstfI4zq+zEIPlLtB26uze5+V4mJe6vDNA=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id li15-20020a170903294f00b001d717e644e2sm827594plb.247.2024.02.12.14.59.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:59:57 -0800 (PST)
Date: Mon, 12 Feb 2024 14:59:57 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 21/35] mm/slab: add allocation accounting into slab
 allocation and free paths
Message-ID: <202402121459.DEFAB0280@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-22-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-22-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=RDzV1lZt;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:39:07PM -0800, Suren Baghdasaryan wrote:
> Account slab allocations using codetag reference embedded into slabobj_ext.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121459.DEFAB0280%40keescook.
