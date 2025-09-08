Return-Path: <kasan-dev+bncBDW2JDUY5AORBUHU7TCQMGQE35EGBYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 80187B49AE1
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 22:19:30 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3dabec38299sf3111739f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 13:19:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757362770; cv=pass;
        d=google.com; s=arc-20240605;
        b=FBOvqxKskhvSpcTEX5PUDl8XDvknyFNSYGbq6Rhl6IuY17bcdfri5krwSKaC0XxjrA
         9YKYyJqxGef5DxC3cOhQCJ37fEfvUIGVKrQD05kTbB3NESmdQp34WbZ12rVI84MK3P7j
         xX4qZ0O4UI9Qjn86DwuErltych60uXrrjQu7YNwJGC31Fv/d2d8odi6SuYK4Tv72IDya
         k0IW2rkK11ntVG8BG1xiw3JhhoN88I5KVDAP31eK2xCwho4gRWaLgAV881lZXEvYFelB
         ZAniCoywXN4xHRNPRBLY+BEMamsKHY2ttqtL7EE5E6UpWWOy1E7Jd0FQww8w6TKfH17v
         v5jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Iq1WF6TsNd3pSUMPgkseJAHf9oMLJYG0EcIEOWgGQ1I=;
        fh=35kI6dy9csjIDove+l97HaNA4mXB1WRZ/1AshOf1Q8w=;
        b=P7YzVwTBqcluAr0dT6625uISjvjKGLTu7Sc7ZL1O8ScD2bqUMxWfXYIfHiqNMGTrRw
         hOcqt1sA1uf+yFT6RWTD4pg4+gzeJ6Y0JVvGPWkoqlj9A8dJlJEayjY02xyFB8nOIMyp
         CjlfEnyYuD8PSrYovFKdwcO2jlYKqIhu/j4NVqMC47aANe0c/sjKYgMx+EqXfB6nGIDA
         MAfzKWfjnQcD2lhAjFaDw5eWX1gYgAfLtsDckyvvv9op/CedKD2kpse22wJN9lFLe+N7
         aXUg7E+bgSLtia7co0bKFnrUI55SXsU6m/7ETlfRdI0F4QfNCjCHmAczMEn5Hif9vePE
         bjxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FF2KN55M;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757362770; x=1757967570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Iq1WF6TsNd3pSUMPgkseJAHf9oMLJYG0EcIEOWgGQ1I=;
        b=vlbtSx7FzWkTgHfcoyAcNA8o7j7ZXnmcURdGuUCgKPrceB/C3/uYwmkMyKFSYxAdrJ
         ycsZcACozjC6etcejsma/QnAXab1uFqP+JNdVBLDZ7OYgE+t+WgSgXVabaK1ZAi5VBrv
         SV2WP6fIuYb+gopcsXNUZ00Qr5P7txmV0wyqxl+0e0YBgEY8WVPnp04lam+30MwbDfn5
         Kz1KrBrQGdUWmsYAyHSVmY41IvUNmf0VfpGQ85uvuRb+Y4YWc519t0xOp+VCsOYwex2F
         L73Theefq0SlgicZ+XEtCbtaGHQiiaTJ0w/a4ubsBKx9L5FzPJoPULwWZfvDAUN1Knef
         ZJ3w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757362770; x=1757967570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iq1WF6TsNd3pSUMPgkseJAHf9oMLJYG0EcIEOWgGQ1I=;
        b=Aq/rb2vcqTcrCH1Lcf9PsrVaAuSOz57EDzpRzPIdJKOInDvjqQJRFa3Vlu69ddv1z3
         2mJVms5nthq7nYla/UMPbkk9cayvTG9Dret3877SpHNGICXgTlii1VpDPC7a0zukeTZm
         SNICPgVOXDUrKor2eNOdtc/SkN9+5B7l4SsGE6Q8wotQpJQCNc6G6L25Ag3LynDyCz17
         QPhN+/aVMhxiXYq6qi81qclgTtwLQne3i/OzwlyrsStDr7iGmysgRIRPsxTDF6exal35
         I147FbB+RwxHeiU1nJd08nWNOvdvwH0ZPOXWr5TP/PIkv18VnCFAnA+y6ppwD1fefblE
         /kog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757362770; x=1757967570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Iq1WF6TsNd3pSUMPgkseJAHf9oMLJYG0EcIEOWgGQ1I=;
        b=Ku3EjaIVOIrwQ6TdJf2o4US/s5k8X13Wey+AO3uwALJygXqxSWyI9keFnqW9T5Mct/
         TKecoE/vqi7DAnNYW4gwceMIuMTd6Nc8kOesvljIUiORyMsfKiDLG+MxSCdmYj5no2Ca
         zg4xWQFBoqpw6sHXo9bHwaqX2dvc2nk3fovkrF4hKuGEBiFPW3XNwhoffRhBEahlExWv
         q/cCkqhLRRnjW6LCp/Nc1qPeGLVcZ88O/nzH812ZT8vRSnwkHBuHuxykMTcWJb9P8QrN
         urOgK4siBHiB8ib0l8WtB2zAMglFmrZIuQCUVM+GdC2IZw4PplkdD+Lk33hx03zY4P7U
         OdbA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeAkjHaxJmahGFarpyBpnvaRb7oGXCD2/OlHM4goitokuGdS6mdlGoBhl86pceSMfgLmHRbA==@lfdr.de
X-Gm-Message-State: AOJu0Yxn7xAvjiEV/ShtwE8DQcJNJYk3AD9EDdeTCM3wTaDu8y2uzwBR
	/ROnFka+VelW8cpR0D4CNgt98gU+EZ7fwUUEJubh9wrBz9UDBwYiNPbM
X-Google-Smtp-Source: AGHT+IGz4LUCMTyYnO6/YdQjfdHqeuZrKLHMcXK13yoY9GL5apqqdruLF4U4vqiJeHHq9dLRsFEH0A==
X-Received: by 2002:a05:6000:26c9:b0:3e7:471c:1de3 with SMTP id ffacd0b85a97d-3e7471c2248mr4644934f8f.14.1757362769480;
        Mon, 08 Sep 2025 13:19:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5f3hlyJPJOZJ2ibI/JUgGJKNcOFGay3HrAYbWj7Yxwgg==
Received: by 2002:a05:6000:26d1:b0:3e2:3e7d:5302 with SMTP id
 ffacd0b85a97d-3e3b6e02073ls1854696f8f.2.-pod-prod-01-eu; Mon, 08 Sep 2025
 13:19:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjBXfpQU9d0LwJZ2XxHWjAnB1193LUmAaohmIU2tHifkI2CRWkNZDDPfaDQuK4POiCqYkKvWbTkYU=@googlegroups.com
X-Received: by 2002:a05:6000:2505:b0:3d4:a64:6758 with SMTP id ffacd0b85a97d-3e642214bf4mr7507370f8f.3.1757362766939;
        Mon, 08 Sep 2025 13:19:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757362766; cv=none;
        d=google.com; s=arc-20240605;
        b=WXqB7MAic0qK9MV0cEIJ2cbAzHqEY+roqrdDa0zGmOy7FNEg5sQNTf7jGfUBqR3Am9
         saEgDSDnMBkeAFAMCnMhavP5zAr2nVtZoVd/5qjUxyAA8lSRTFQlAet9wtVIk2hqkcO/
         kR/oD3R0iwpiYkwyJFc/Yk7OKFE1P76Jv2HFVwpg61p+nYxMYDCxxI9f2r1pVpaMMJVP
         OXiwPO4dWTJIz8UqdGYiiV3LyeFR8U1ODJFfrlI5R67MgAinKvGAy18CCnlVbHMFpLIR
         QPkKWFP9JrcQcQh3HHBLHsqGeLBdkGFBiDVO8ZRV2k6adZmA4Uk5MV8o5WJYTLeB20l7
         mMyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bEKhAzri7BBrxNHU6CjKqcmbERBZnrPEV1ur7Br4EzE=;
        fh=FF7lfloZtZxph+X9QpdIxQxyAmybHs9z9KJyNooDvfg=;
        b=REALAQtRfAmkt2RDN1MJ8jt/k0H/4ZQGclgOgYWUg6UtT2ohk2R45Ps6ggiOU5r1Ji
         EVW9WqD0rhCaL1KyJ1H/VcDvVeB3PcQYQDRWZHqkdWhnUeCGG/3fIh+sge6a6lWxp8Kb
         bwGFW8TfJXjdOZr9gq8TYlpCHMPrDtLT69pPkWN1uakUPCcINOq+OyL27b0a3UhXw6WN
         kdsEE7x9Z5MzNOW7haJ6aw9LfWSxps+inqiOlIC+NIw1+O0hp49FDFe7wnc5ET+oSvEf
         /M+z7AWgtNcLNLek7q8+AJA9ETRXKC4CAVZ051qIpDkvhKFm8/FmQaeduFeU5IpMcN3w
         6gPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FF2KN55M;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3e0628baaa5si286341f8f.8.2025.09.08.13.19.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 13:19:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-45de6ab6ce7so8740675e9.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 13:19:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWgVWo0AqC0acbC8pPbmQzm2H6BHjQiX4XXaO+2fMky6LyatQgmJMfc/yxJGAzOT4SvZ9Uelu+ftsw=@googlegroups.com
X-Gm-Gg: ASbGncsD0YVGn70mZ/v9tmbgFiFT7W1dMbbgD67CqKa4uWNQjIqLpLYrFXkRJteO61f
	aisLMXATa9Qrkq9JARPc2h+u9V40vn062fNsrwp0apzI1Xhlr1pIkd52oXTRZBxKxSN78soZ2ei
	zjr3amkF+hoQP+OaTk6jhdcYa1iMsJyvvqU5dJObWx/OMDQNdxoN7IgLprYar/qjK7aVXavzLO/
	OTvahvgNNIqMuSllUs=
X-Received: by 2002:a05:600c:35d3:b0:45d:98be:ee8e with SMTP id
 5b1f17b1804b1-45ded05bcd0mr4878465e9.1.1757362766098; Mon, 08 Sep 2025
 13:19:26 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <3339d11e69c9127108fe8ef80a069b7b3bb07175.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZedGwtMThKjFLcXqJuc6+RD_EskQGvqKhV9Ew4dKdM_Og@mail.gmail.com> <2xfriqqibrl7pwvcn6f2zwfjromyuvlxas744vpqrn2jthbzu6@nrhlxafjpfnr>
In-Reply-To: <2xfriqqibrl7pwvcn6f2zwfjromyuvlxas744vpqrn2jthbzu6@nrhlxafjpfnr>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 8 Sep 2025 22:19:15 +0200
X-Gm-Features: AS18NWDjLBMTDDx-3GcgskVrIFrWTkldm4ARgshAhph95s8X05Rv1arvNW2pjfU
Message-ID: <CA+fCnZeem3pBPfhQyPiSAUfp5K0YdHFuRs0FZykF03YXVS-f1g@mail.gmail.com>
Subject: Re: [PATCH v5 18/19] mm: Unpoison vms[area] addresses with a common tag
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FF2KN55M;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 8, 2025 at 3:12=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >Do we need this fix for the HW_TAGS mode too?
>
> Oh, I suppose it could also affect the hardware mode since this is relate=
d to
> tagged pointers and NUMA nodes. I'll try to also make it work for HW_TAGS=
.

Ack. I suspect you won't need to provide two separate implementations
for this then.

Also, could you split out this fix into a separate patch with the
Fixes and CC stable tags (or put the fix first in the series)?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeem3pBPfhQyPiSAUfp5K0YdHFuRs0FZykF03YXVS-f1g%40mail.gmail.com.
