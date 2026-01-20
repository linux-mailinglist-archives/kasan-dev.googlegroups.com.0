Return-Path: <kasan-dev+bncBDW2JDUY5AORB5MCX7FQMGQEDJ4AZSA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SENbAHjBb2l3MQAAu9opvQ
	(envelope-from <kasan-dev+bncBDW2JDUY5AORB5MCX7FQMGQEDJ4AZSA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:55:04 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 8870D48EBB
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:55:03 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59b686eaeafsf4657231e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 09:55:03 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768931703; cv=pass;
        d=google.com; s=arc-20240605;
        b=e8GcW3BfjiV7w9v8HpvaQFn88Ovm1uzOetnHoNJ/r7EmbSwjyNIU63i41NKdYkA3j6
         qy5XZX+qhb9UPhX98OED2U+7OWT84SJ6MyKxCuhVsSYkWyqtytw0REjI5rkVIyyzc3hg
         /yaY9mrmrnqwBk+m4Mly3qYuz689sOjJc5xKc7wl7lZTQO1G+XJDsZ1vtXMCQ+cK/PZU
         y5oyn4Pez5nYndd+bF74RMIHcpVdoi51/rkMyUYbXTmRlZ6qCJNnVx3bjUSG1+yVMZ+i
         vF6Zls8BfYxu1HIsPuDX6HFdFE+aOYR5YBlO5RHOf6hvVZ/UGwIxgbFeT38koYyfBcuG
         UEVw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=dNM+u7FLklLhk/0KDFlTS9DiJsMTxggukLuJcoXM2VY=;
        fh=EMV8OEcW+mCF6snnOJr/uLSswu4I0hlPdgzAYh8uApQ=;
        b=QPK0RAAUnWoVq6GSSaFySC+BNejpThxsr8YnuaKxfV2yuXlOW1L3ZBXIT6Kgt7bOfE
         /s5njHPp/JbA2SFnG9lWyvhNhlC/IUe6LPgqmQ2NbpBtbHRtrOtAJHVBs8isGsto1nKh
         WCcNvg5G4OV5srIg0UplaJDwYthD8hLcbNRBP0tFp0eWNhd1FpesIthNdarrLwePkhl+
         6HQr9TvFPJinsZ9gdPgTaaohiMTfJ+Sfss4WzqWdAVEE1vA3rjUJDAdjuU3UJK/uwiMm
         CR7+fgZkzLYHQ5z3SdpdenMw0AeOwCKAXfhHlhh2tV9fidIyTH3Lm3+nv6hctWXoezuU
         h/lQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="GFrwUW/H";
       arc=pass (i=1);
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768931703; x=1769536503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dNM+u7FLklLhk/0KDFlTS9DiJsMTxggukLuJcoXM2VY=;
        b=r/LdbjiXTVFWu2hcrd2zaA9mils9H4LrgjW7N4D+KG387tlvarCHOuI1ij1dFDDyQF
         of2W0VtKe77UaHikyLAS8W2+L2Guw3IVuq8JZIbiGYVJyq+LQL/QlcNhqEY6qAXrTdQZ
         Myu6+/zEbTkVv+KYMPd9ZDtdxEhGTLOSnBr40bRrs9BxRRNaqg9mbfFZ+0oSvu1/suNA
         dcxTCKNRZEiBu27bgbEijNEoJpSXDA0Qgbz8g6hMy4pTagKvqYWPSI04QWnS/QAi6pF+
         66quZFCtxHUK1bIwVOYDosh0wWF53sVrBiWH3GMi1DilLQfxVs+3Jz/xgvcodvZgQ4nV
         /2wQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768931703; x=1769536503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dNM+u7FLklLhk/0KDFlTS9DiJsMTxggukLuJcoXM2VY=;
        b=TeQfUPkG0uvGe0wKlvRmlUh6GrH+FXhWJJsUEoh0jAzqA3asCNYAnIaeh4l8ZwhZDJ
         6a/4484WcWvNzAqnpsbwblvh0NNeW9oUsaigzvBXyqEKECp8HYZNCwcTz7tOuO9gxQJ7
         6h3w/XeWQmcLLfLJyf1YOPRdvvTOWEep/PAkzLq67cqA2M1wtxaOOgbqGdckA6m7AgSI
         P58SVt7bliwFAZBt9RhD7w/EPPdkEsVIFzpq0bSVg7CVut4Y3tZkuuqglgA6tRGB/ZHx
         iYqnbNA8Pews+cs0JjGvj4h6pIxX2G8Rb72MgYCUQ3KDgdYLPXUA0OkFSzyKmgrcjuvs
         kYKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768931703; x=1769536503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dNM+u7FLklLhk/0KDFlTS9DiJsMTxggukLuJcoXM2VY=;
        b=hjaEm+3lXCvtafnmhUSXo5UUQfxFf3e90IZ8FR1ASUT+pltU/WyZ3w6+GBiispjdFh
         M+7SnMyCaIwKjvFc+URNVxkWTajVGrwRWGWc/UVEYfa1QkH4W3GgO4Xr2piYwHI+58OI
         fI0TXmvkySqNF3NVv7RqrbPlvbwxbZQhN3XyAACNQw40zAoVcxwZJd9pvvWVyEXs6A0a
         EturMnbEQkY2evxwObG3BvhpA+IYsxhvw5BDGTrdA5tkfgu8s0QOfvPpF96naSsXjXuk
         CpilSzrUFIZglK2rkvTPhTtmjVO2bMjIDzofTyVn2vB7+LwkHr9KporpAeFPRtN1IGQm
         3RvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWzSOscVXGPU3Y8+0ZJb+NUtJynWkI95RrM8y8Oy3lvQ6OHzngE8uAMB9PqOs7geb2GiW/FUQ==@lfdr.de
X-Gm-Message-State: AOJu0YyY5xsVcXEGjqDb0VGF9aupIXFIRqbWryFAZGMcsBD+r7u6Ulmz
	ZR7y5rvDy31iRRpUi6JT9BCp3Fwm32oN/gvzS68JKLE4q3qvX4ybod0W
X-Received: by 2002:a05:6512:378a:10b0:59b:b037:489e with SMTP id 2adb3069b0e04-59bb037493amr3794784e87.4.1768931702498;
        Tue, 20 Jan 2026 09:55:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H51A5SyclrisrK4uakaDF71IRPrLLKNrpraR7ZrEvBdQ=="
Received: by 2002:a05:6512:3f02:b0:59b:7205:469d with SMTP id
 2adb3069b0e04-59ba6b511cbls1992432e87.2.-pod-prod-06-eu; Tue, 20 Jan 2026
 09:55:00 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVwQWOylg+hhNYOGKPfPMam2kblSjkLFM1O44wWOeE4QD/B9GuTFia5mc3Wgkkm4s3sfTaf2tywyGw=@googlegroups.com
X-Received: by 2002:a05:6512:220b:b0:59b:7947:f420 with SMTP id 2adb3069b0e04-59bafdb6c2bmr4353089e87.18.1768931699784;
        Tue, 20 Jan 2026 09:54:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768931699; cv=pass;
        d=google.com; s=arc-20240605;
        b=fYTAhK90oFKNECCGCBQnOv2edzMWJcGhyetJB4A57t6e4FwbTDz0qq70BXbKkd80Pt
         kswgl6bgu4LVxc7R6Yazbk2J8dpwRg2SPNwlAFVpPq3urhSHdGltD8R4z9YDRDqvBcDp
         uH7IDydKzE7Tzke1gUBDgcm8ZFM4nzhw4sQDt/dYRRrjdxRaWN1fe9ndrCPCEU2fF4Dj
         HgCsfaiz2bsPEMBualikd/a9eTDM+As+Y0MbhrKO71mfBUrg1Axpo9Cx+J2qjDqS2G+a
         rHfo8cjeUSHmgAQKhy0S9AQa120XkchZhXQRE7AnXTezn6FBuklX7mal5VzDp8fGpPz2
         C7iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CSI8A4TsHJKLPFzycUoWUfFc682TNPoMjAF0fDDKMCo=;
        fh=bfA6wFIfrvZ/U403QHNEy2OvMq6hFyb23N6Zq/4TX6k=;
        b=b1UEO9GRmarrWQT8W4C4/IMog3SeHmchrMJ3qPGc3VOYL61HPivdvIlb9HvN7x0QnF
         8bVf+f3loDDJpRu5fEaoE18MOM6g0iy/qF0BGfI6qob/V8P+6s8x/z5YWjn1UigWru9U
         49GuUaC3O61ftCLth4szGOiYKsO/UgJIBZBZxrZ/8a5fpsvB9JXtIGC4gJZ8sxnCQLSH
         ngnFYCbohIcjiCoZTH21MGUsjIGKNTyJCI8NABrMknTBiiXinGJJ/ZMbTzQpvZMIoMOS
         LQsGgf0+Mf5Cwh83VOKUzaRwK5btWdIjhHxfHhSCRWiqRDGe2F33y3ApnHDY/EzHIWwI
         wstQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="GFrwUW/H";
       arc=pass (i=1);
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e285a2si3104091fa.5.2026.01.20.09.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 09:54:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-47edd9024b1so36746725e9.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 09:54:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768931699; cv=none;
        d=google.com; s=arc-20240605;
        b=PGoqvH9Nm1gl99WVfqU8P1+55LnCUS/bL5AMTIbn4sAV2flwzrFxAzsA290m6668CR
         KwhS62LEMHVUf+m5wA2rSuHoCb95KT69QoiHNNccLpqtERdV2H6TwwDwHEOmQfWpnnjb
         jhqwzplIhIfE1mV7L++M4HkL/Y14pWhzoBWxpGRVZrdXWJ2MU6Prf9OTv66T8lv+u1Gj
         iXrPOJMdt962omz4bEp7zqBxw4WLm08G+Th15fibOONgpCqOXONHoZEymf2gqIFILtoV
         8oIkx0OllFQvOpaMh2+o+Do4x+gIdBdHkfSxY6N6CfRyIOG15280dwbWSHWRPdn4LQ2q
         ZslQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CSI8A4TsHJKLPFzycUoWUfFc682TNPoMjAF0fDDKMCo=;
        fh=bfA6wFIfrvZ/U403QHNEy2OvMq6hFyb23N6Zq/4TX6k=;
        b=KjHtdCeSa6qQSdC3ptwndAnzhpm5cc6R7AK2Mn0RtCPDdP/r6C++cKuqd2jHJAy1nu
         HV+8i0gCkwzN2Gp0MO2Gfw1Lk9DgNjaRWuczmkF00O4tPO65SmqqIMC6SudwKRYawi8c
         ChtC7c3Q3/0evFUr0y1oY7XBg1d2Jry0WNlXd2GUlaP4hNGuk85AJdYFaOH0OLDBQotp
         V+uGti7feXXE6gMes14Rkao0w4obfIs4iaDd6WtJ2Lg4oVFPlcSamLZUtmlXJT53U/7m
         umeN3q4Pak3rg+iRUdTthkwIVyJOFxPjLSl8wzV/a7er1n36F6DSgiIojXf0ZnswUZDq
         0/Tw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUGkAc0K1HWv/BfPPvWrE2o4QEIM2mX8XgP7+M3MWYqk3X0Qa1+DylKvXc00IjTSudXIEbHy49mOss=@googlegroups.com
X-Gm-Gg: AZuq6aLTaHcn5974jYocDaxSYNR2F6BdLuGsdoT3Wrbt3QhpFF4Eb8HjobGGk32HzsU
	hYD72/SIhKycWE/NWouIwAfdRtYFJ0r83kHW6dmYrrPT+i0J7SXneZu+aB0pteUzOpdoxOyDY2t
	k7hsq955RI2BIt28KYTAHx2Pr4mkNom9k3rhOY9vIhCfEignsFCAYDIwsX45I7LqGQswyENeY/h
	XaTn1VCDLHQ/mcHaDUqE9O6VWCymITCR3uh60kIf7WQuzrjOGz66EYyvPXFqzvWUYYD2m+LvYnc
	VFv1r2jAWRXYG9M76fhrtO+9t2XJNw==
X-Received: by 2002:a05:6000:310d:b0:430:f58d:40e5 with SMTP id
 ffacd0b85a97d-4356a051bbamr17722513f8f.30.1768931698830; Tue, 20 Jan 2026
 09:54:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768845098.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768845098.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Jan 2026 18:54:48 +0100
X-Gm-Features: AZwV_QjKpw6bSXc49tC7Ft6D0ET5YLTkUvlrSRTXNNU3JrK5sgQbId38njXfil8
Message-ID: <CA+fCnZf+U3RhmMeGxQ-UypJw2yGd8RJ0gFKrCXsC1eQ5YO-eXw@mail.gmail.com>
Subject: Re: [PATCH v9 00/13] kasan: x86: arm64: KASAN tag-based mode for x86
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: chleroy@kernel.org, surenb@google.com, justinstitt@google.com, 
	nsc@kernel.org, jan.kiszka@siemens.com, trintaeoitogc@gmail.com, 
	dave.hansen@linux.intel.com, ryabinin.a.a@gmail.com, kees@kernel.org, 
	maciej.wieczor-retman@intel.com, urezki@gmail.com, will@kernel.org, 
	nick.desaulniers+lkml@gmail.com, brgerst@gmail.com, ubizjak@gmail.com, 
	rppt@kernel.org, samitolvanen@google.com, thuth@redhat.com, mhocko@suse.com, 
	nathan@kernel.org, osandov@fb.com, thomas.lendacky@amd.com, 
	yeoreum.yun@arm.com, akpm@linux-foundation.org, catalin.marinas@arm.com, 
	morbo@google.com, jackmanb@google.com, mingo@redhat.com, jpoimboe@kernel.org, 
	vbabka@suse.cz, corbet@lwn.net, lorenzo.stoakes@oracle.com, 
	vincenzo.frascino@arm.com, luto@kernel.org, glider@google.com, 
	weixugc@google.com, axelrasmussen@google.com, samuel.holland@sifive.com, 
	kbingham@kernel.org, jeremy.linton@arm.com, kas@kernel.org, tglx@kernel.org, 
	ardb@kernel.org, peterz@infradead.org, hpa@zytor.com, dvyukov@google.com, 
	yuanchu@google.com, leitao@debian.org, david@kernel.org, 
	anshuman.khandual@arm.com, bp@alien8.de, Liam.Howlett@oracle.com, 
	kasan-dev@googlegroups.com, linux-kbuild@vger.kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="GFrwUW/H";       arc=pass
 (i=1);       spf=pass (google.com: domain of andreyknvl@gmail.com designates
 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDW2JDUY5AORB5MCX7FQMGQEDJ4AZSA];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,google.com,siemens.com,gmail.com,linux.intel.com,intel.com,redhat.com,suse.com,fb.com,amd.com,arm.com,linux-foundation.org,suse.cz,lwn.net,oracle.com,sifive.com,infradead.org,zytor.com,debian.org,alien8.de,googlegroups.com,vger.kernel.org,lists.linux.dev,lists.infradead.org,kvack.org];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_GT_50(0.00)[61];
	FROM_NEQ_ENVFROM(0.00)[andreyknvl@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:email,mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim,mail-lf1-x137.google.com:rdns,mail-lf1-x137.google.com:helo]
X-Rspamd-Queue-Id: 8870D48EBB
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 3:40=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> Maciej Wieczor-Retman (11):
>   kasan: Fix inline mode for x86 tag-based mode
>   x86/kasan: Add arch specific kasan functions
>   x86/mm: Reset tag for virtual to physical address conversions
>   mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic
>   x86/mm: Use physical address comparisons in fill_p*d/pte
>   x86/kasan: Initialize KASAN raw shadow memory
>   x86/mm: Reset tags in a canonical address helper call
>   x86/mm: Initialize LAM_SUP
>   x86: Increase minimal SLAB alignment for KASAN
>   x86/kasan: Use a logical bit shift for kasan_mem_to_shadow
>   x86/kasan: Make software tag-based kasan available
>
> Samuel Holland (2):
>   kasan: sw_tags: Use arithmetic shift for shadow computation
>   kasan: arm64: x86: Make special tags arch specific
>
>  Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
>  Documentation/arch/x86/x86_64/mm.rst      | 10 ++-

Still missing Documentation/dev-tools/kasan.rst updates. Feel free to
send as a separate patch to avoid resending the whole series.



>  MAINTAINERS                               |  4 +-
>  arch/arm64/Kconfig                        | 10 +--
>  arch/arm64/include/asm/kasan-tags.h       | 14 ++++
>  arch/arm64/include/asm/kasan.h            |  7 +-
>  arch/arm64/include/asm/memory.h           | 14 +++-
>  arch/arm64/include/asm/uaccess.h          |  1 +
>  arch/arm64/mm/Makefile                    |  2 +
>  arch/arm64/mm/kasan_init.c                |  7 +-
>  arch/arm64/mm/kasan_sw_tags.c             | 35 ++++++++++
>  arch/x86/Kconfig                          |  4 ++
>  arch/x86/boot/compressed/misc.h           |  1 +
>  arch/x86/include/asm/cache.h              |  4 ++
>  arch/x86/include/asm/kasan-tags.h         |  9 +++
>  arch/x86/include/asm/kasan.h              | 79 ++++++++++++++++++++++-
>  arch/x86/include/asm/page.h               |  8 +++
>  arch/x86/include/asm/page_64.h            |  1 +
>  arch/x86/kernel/head_64.S                 |  3 +
>  arch/x86/mm/init.c                        |  3 +
>  arch/x86/mm/init_64.c                     | 11 ++--
>  arch/x86/mm/kasan_init_64.c               | 24 ++++++-
>  arch/x86/mm/maccess.c                     |  2 +-
>  arch/x86/mm/physaddr.c                    |  2 +
>  include/linux/kasan-tags.h                | 21 ++++--
>  include/linux/kasan.h                     | 13 ++--
>  include/linux/mm.h                        |  6 +-
>  include/linux/mmzone.h                    |  2 +-
>  include/linux/page-flags-layout.h         |  9 +--
>  lib/Kconfig.kasan                         |  3 +-
>  mm/execmem.c                              |  9 ++-
>  mm/kasan/kasan.h                          |  7 ++
>  mm/kasan/report.c                         | 15 ++++-
>  mm/vmalloc.c                              |  7 +-
>  scripts/Makefile.kasan                    |  3 +
>  scripts/gdb/linux/kasan.py                |  5 +-
>  scripts/gdb/linux/mm.py                   |  5 +-
>  37 files changed, 312 insertions(+), 56 deletions(-)
>  create mode 100644 arch/arm64/include/asm/kasan-tags.h
>  create mode 100644 arch/arm64/mm/kasan_sw_tags.c
>  create mode 100644 arch/x86/include/asm/kasan-tags.h

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf%2BU3RhmMeGxQ-UypJw2yGd8RJ0gFKrCXsC1eQ5YO-eXw%40mail.gmail.com.
