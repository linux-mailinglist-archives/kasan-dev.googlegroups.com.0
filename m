Return-Path: <kasan-dev+bncBDW2JDUY5AORBY5GRG7AMGQEONGC3GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D49DA4A6F1
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Mar 2025 01:23:02 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4393b6763a3sf11279765e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2025 16:23:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740788581; cv=pass;
        d=google.com; s=arc-20240605;
        b=TsJ8XxC9u4HS73Tqy1gf2HQmEtHtatR3WdEDaYuzZKmNPx+vfwQwNAvbrx1n/+zxUu
         Ll0CosRpnfm1EOFIPNcp7xLug4/5+/aNpkdP5qmKupzvyM1iUnXXNqCAcZy+6vim+/cS
         JTPR45eEnCiDL8d0at+fsu6YkFaSgg7SjKfmNGytH8fuK5QHjPfPgYNoG/v+Rs22+siY
         PM56BlnYb0TSN1c25agZ+GRiFuDZ0k5beVkd61f4UvKzrLMwwG36aJT9thq+Xty1EOLb
         lyr06DjsTf6vLnhtPhPXhfXVl8k6158g8w+ttL8NyJVBOAzj6lo+OLZcjFWS5TbTblFc
         0p0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=3ScnBVIfQ7zb3vdtLGTXahXbv5gUo+WIZAOjvsCRt/I=;
        fh=X/Z91Lg92gBMNu4aR8TGMpM3sfG7qpGHPy3UCIkoWD0=;
        b=cW82vx9DKzKTNACOKvlb8lXrDCKzV6zv5tlLfKviAY6GmkpbZoJRlzmghoDW2/GWAj
         nceWEYDU3B8qtPXAog3nPL5V+FqF902rLAKCq38nrFLohEHEZ0yO/9fFDCbzW6+S+I4A
         5z+5vU4bsgA9/H+1/oj271fjnHqy9oJOpm1hsKZnO8Src+Rwhm0H/TxRVfbME0zm961R
         rhwb/WcqEwfcZave5/Yr2+KYj90M5ogXfsbGgs8Mx5nRktVAk7NC6aY7PsG71RUk6uiW
         2KHNEBoEhFuT/D1eo9/+reeP1wFL3so39zFow1pkEmT3fOoSayzUIXBZBuzofGWNBtXf
         rBxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WpEv1QwW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740788581; x=1741393381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3ScnBVIfQ7zb3vdtLGTXahXbv5gUo+WIZAOjvsCRt/I=;
        b=Dc7rYrEu0RZ30CtLd6QzhIZN54fzQZP4q2Rib6cYOTsPyLzmBMsEekXQdBPX2rRCoJ
         2zvasxat7MQNt/3DYU5RnrN+FOn3oxy1MFvmwQlUVZG0fgk67tnkMQfk4DlW979rsNnl
         viZD9tV6oLoZmg6CUrIGhZuYfChONvLf3bEW8Oryp7VlqNOEDrXZ6SPVed2/0legwjam
         VL07khWvdkG97nLFtvMXdJNtp8Sh0smhHy8J7ll5tiDeGIwuxjDFWPz9jTKDxvid4/Wb
         AAPwt1eN4g0OLX98viUoeQHt0qUmBcJIPqJBRBqUriFrvo7d5dGyh1zouaoXw9sGPeLd
         jCLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740788581; x=1741393381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3ScnBVIfQ7zb3vdtLGTXahXbv5gUo+WIZAOjvsCRt/I=;
        b=OGG1kZ7uKqMazdwU7Yu797XmIxZNSasKCs5VbDD0LkAu+Ew+51+1G2PtrSdgeGW72i
         c25A6Uy2D4xtoRIDNd6niKiShLvyHchAdm68qdzNfJrTo3rx/LnSuW/Z7dPLXSOmJ6HT
         8nNNJFrqWaZnoG1F1kiLD3NBvmSOSq/tDGN7nRdeeisw4Sy/tXGWpGVd6AE70Bi1L54Y
         CrANwsDCFh8YdT+wV8aM9gnvKZQiMXjUPSIr2Xh4Gz7Ih7ylsueWEf2dwQC1U+CjG5+X
         TNcAEuHZdEK7k1c3D94K8NK6XBF2DODaDoMmktn3DquUCuhyC7DeLufQ4qlM4bi302kr
         09kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740788581; x=1741393381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3ScnBVIfQ7zb3vdtLGTXahXbv5gUo+WIZAOjvsCRt/I=;
        b=d9JuX0e0cVhPH+NeFGKiK/pzlHba5+XaFMdTmdwykobm9O3y/p5jo4pMfJBm5YPOE3
         TqaM733qVlfnNK6gBwbGqFrQ1rtzO2vX2pLU8M3M7ipOFtfwj0KPwEQ21rCn/XgE7zJB
         YL2v/KDU5ZOrzsqotM32/rab+HNpz8SskwzNjw4LuRPOvg5MaoUNeavoegaIY4pmYYEX
         059F05ahcFuSoZTcE5aFFViF2oZscN0o0SuF/0BTStfbtSWVTq4V6K0Emg8CvyyjS0zN
         ZpFtah72DqAmfRmR10v/i3eilmrcvY+EyUfVACBri/mPLVvFvRqAmwd+tDYAYBE7SU1t
         TjmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6BHL8FEWdlfRBK3Qy4uk/TaZz4MuamBv+kg+oT+5kL7h2JR+SA8qiUnIpzVbqXFHpx4Q8wQ==@lfdr.de
X-Gm-Message-State: AOJu0YyeZ1Zs0YKMJqAEnvFvLJ61lIGmUuJtIFHPh2ZYSNmaJ+DJ4qvU
	TqEkhu8UTUGM9kLknk0LZSwQKVOig/Uc2C7I+LMWDiG4s+CB+P+y
X-Google-Smtp-Source: AGHT+IFRmPpv4Uj8NYJHbTLiZ2+p7fwnD69A6GJUamFEnBT+sioyIsaF8hCmSJI1k7tY7OgR8Bhpag==
X-Received: by 2002:a05:600c:4ec8:b0:439:8b19:fa87 with SMTP id 5b1f17b1804b1-43ba66de874mr42669775e9.4.1740788580344;
        Fri, 28 Feb 2025 16:23:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEbsnluLlMhxDRUG6vLoN7iMJlAyimksnNOYoXhqI3sEA==
Received: by 2002:a05:600c:1c0b:b0:439:8aa2:6464 with SMTP id
 5b1f17b1804b1-43af792487cls11851255e9.1.-pod-prod-01-eu; Fri, 28 Feb 2025
 16:22:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVkz+vH2n8BgfJUTrqY7tTac0Iy/JqKalaYmMSaCvNO57Ec3Wu4kq7JbNVunR1hUz0gP2oPsTf0NAc=@googlegroups.com
X-Received: by 2002:a05:600c:3b0d:b0:439:88bb:d02d with SMTP id 5b1f17b1804b1-43ba66da7eemr42167305e9.2.1740788578244;
        Fri, 28 Feb 2025 16:22:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740788578; cv=none;
        d=google.com; s=arc-20240605;
        b=Gd4uDFmk0/NzLUzRGBdf08CqN034EZlSy462JYS5NnUDO939lNKu/51M1v5kHTbP1W
         nxgwsF+es07gruLfMLik5JCnbMKuKHYlz6pQebohVTtr9HH+5wghPVlRd6CJAXgEUMc/
         rHpJU6jyKGUib3j8qeTe+3k+FM8lFsV1Q9YB405kmjCTZZAFU61nEHBNaLcNvZAtnKYl
         SrFrnIUIHfJwGCJF4fTydF+1P3strvcbAP+Z8vfhEmpwzE6DZESXGkXrC3ucPcbE4hoE
         A6n8QqD/4fBmVEVGsnKrV1i5YY6VtINFODY2DICU4vR1T/iHipPt500Aw2icA79vRj9W
         21VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BJ85jd9LWmkfvxQt+PubnvRoJI2+CN6NMADWkuH7ehQ=;
        fh=ATLj9/VJvAnKVxFyX1kaufbLsXR4q8Dg7Nh/f3eQ+Nc=;
        b=SMJnIaTLrX+G2eOTQ/NPPHvhTPCqRbPWQrQRcYFRpB+7wTnxb50xjhXZYZEbah2Bdw
         HsZxtt0y4f8wBo0pDacKG36Cm8+yPFKVuQolz1R0c6Wiu6f3mjBlrAWwvcAtkW+9tsnG
         oiqrO5wZgU8LLxqgqOSqmpEFgHQGI03HklmuXOOLFfx5fTQVfrT3JijUS03l3PPFFbwb
         7q72mqjz6NtW9Et20xopnEHFxbdoZJVrT3mazwxFbGUIouGT+nslKYpSzeSur62Rar4q
         h8LUA8bdlcJMQvURU0J8Kb2+QPfkCO9iQ6kW4wgXd6FMKn1OLgrkdBqwORtr3WSbicMX
         n5oQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WpEv1QwW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43b73712735si3917955e9.2.2025.02.28.16.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2025 16:22:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-390df0138beso1488624f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2025 16:22:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUGLN32UX8XW1kIbgiBr+sySLsyO29sS4vyU+JWlDMR3HT9ThzgZP/LT6B0uQxQDk8pME5baFR33uM=@googlegroups.com
X-Gm-Gg: ASbGncu7COKBTKp6ly4zQN6OyxWo/GZTS0xJqOXZPkfbmYUIxPI/LPVsF7R64LOcG+7
	+UddSlmce/xlIIEoiOdA853R9PIC1+ulkB2EM+0KmSSb/nTJ66/SbYVq1S0bb2thupfqz+5+DuU
	3zpMIbXCHyd3anph5pqzdqwHbohI7y
X-Received: by 2002:a05:6000:1849:b0:390:f698:ecd0 with SMTP id
 ffacd0b85a97d-390f698ed13mr2102576f8f.11.1740788577700; Fri, 28 Feb 2025
 16:22:57 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <CA+fCnZfb_cF1gbASZsi6Th_zDwXqu4KMtRUDxbsyfnyCfyUGfQ@mail.gmail.com> <paotjsjnoezcdjj57dsy3ufuneezmlxbc3zk3ebfzuiq722kz2@6vhollkdhul7>
In-Reply-To: <paotjsjnoezcdjj57dsy3ufuneezmlxbc3zk3ebfzuiq722kz2@6vhollkdhul7>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 1 Mar 2025 01:22:46 +0100
X-Gm-Features: AQ5f1Jp9iybs6pTKPBUq6fE1AmEKUlDJIkwe5Kr9NN_-2VapuhLDqeATKkl6mP4
Message-ID: <CA+fCnZcCCXPmeEQw0cyQt7MLchMiMvzfZj=g-95UOURT4xK9KQ@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, mark.rutland@arm.com, 
	broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, rppt@kernel.org, 
	kaleshsingh@google.com, richard.weiyang@gmail.com, luto@kernel.org, 
	glider@google.com, pankaj.gupta@amd.com, pawan.kumar.gupta@linux.intel.com, 
	kuan-ying.lee@canonical.com, tony.luck@intel.com, tj@kernel.org, 
	jgross@suse.com, dvyukov@google.com, baohua@kernel.org, 
	samuel.holland@sifive.com, dennis@kernel.org, akpm@linux-foundation.org, 
	thomas.weissschuh@linutronix.de, surenb@google.com, kbingham@kernel.org, 
	ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, xin@zytor.com, 
	rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, cl@linux.com, 
	jhubbard@nvidia.com, hpa@zytor.com, scott@os.amperecomputing.com, 
	david@redhat.com, jan.kiszka@siemens.com, vincenzo.frascino@arm.com, 
	corbet@lwn.net, maz@kernel.org, mingo@redhat.com, arnd@arndb.de, 
	ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WpEv1QwW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
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

On Thu, Feb 27, 2025 at 1:33=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> Btw just out of curiosity on the topic. If we used a runtime specified ka=
san
> offset, could the gdb script issue (not knowing the offset at compile-tim=
e) be
> fixed by just exporting the value through sysfs?
>
> I know that in inline mode the compiler would still need to know the offs=
et
> value but I was curious if this approach was okay at least in outline mod=
e?

I think this would work, assuming that GDB can pick it up from sysfs.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcCCXPmeEQw0cyQt7MLchMiMvzfZj%3Dg-95UOURT4xK9KQ%40mail.gmail.com.
