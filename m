Return-Path: <kasan-dev+bncBDW2JDUY5AORBRHQ7C6QMGQEUEDSKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id A6826A44F03
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 22:38:14 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-543bb2be3dcsf3740649e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 13:38:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740519494; cv=pass;
        d=google.com; s=arc-20240605;
        b=jr3KQcwgEX26Ax/g2e6ERsHRFEqDNy5h3GkFVhCq29bpxhZ9SUuoT0PJ2tAMwQQIml
         5UCHKHwn9JZ5Owue5V6eo1n/LHKyO9lZFe0JTGPi8jfX1DhFmne6vh7COItIXQ6Wooqn
         5SJzthHAuHJWOzDGa5Rsh6b1DshORBWec0mjPC9JhUTmcJW0XaR7F3TlwcDtRH/U+7IK
         usEZMffRAHhOKOqW5ySXXRi6NlP6XfZXlip5SpVJu1jw7i/PUaLShSrV+vRjSMKNOn74
         NutIk+VDnhxqjiKgdsR8LY6fL0xgt41nPkSroLHLm8RH3ofH1yeKcOQcPPGaco4xHhBg
         twUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=6CuZ/gppdjo5GNBW4cFCKjZu7BN7CD5DyBPM6OcMKTY=;
        fh=42UY0sV6n6dpUI/yQVPz1ij3+YOm8JrL1nMvd2mgDZQ=;
        b=PvvQKgAXlqAfTN5cwmVfvAgR/ll+i/9d+7YPaXXz32RjEIRONie3pcu51snRONBleQ
         zAb8vmZSfrsCUOGlIta2K3+HGJue4HyIwGR8jhLFMK0CC5f69BZTRfaYcagaKbyrzydI
         k2+cioHNEE/w8QGKFsq1CGETGtPT6G1CSk61OaomVtiCdc6oYGrjFELqCD/TREUSJlE2
         YFBpHtRVAP6OIdHT/I5Jt1UoQWYbKr1ISvOhgC3UUhlgUcGItUEoNfCfJ/Z0PHYVWu5v
         nWDSTl1YjVHRESfX0w9hArcrXXBTpwvyS0vtN4gI7/slI1/g76d949sxz3X4/NUpW30Y
         uQ3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T8bmA6V3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740519494; x=1741124294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6CuZ/gppdjo5GNBW4cFCKjZu7BN7CD5DyBPM6OcMKTY=;
        b=IyCFMLOF0sh+ND+qr9oetXKyTu6A1x81rk/g0d5X/o6H4GOPjZkb4p7hf94bxwMXB/
         jSlraYygjsxCcaLlHeZ4ClTO4VZMBjELYDLyohl/e7SkcOsYIogkqOWkHblSITrK1KTb
         /yvSsl+yBg4xAXi7Q8l1D5iqEwOh5QfuPt0w/DMSQd4ihbp+LuPGVGiXRxF6SKcb98SR
         +96gNMAoMeeVhwmeIwzxqtU3pZwvilx+AiaXgp+yt9ResYZinlipxlQOMLoj1HlIIRzv
         Dv3fgQ0Yt6Qh/Hh4QRrZueMVr4UIwC0FJda7zKDKX/gpaOrBr8fUxSA4S6x6YisoP8mR
         VlTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740519494; x=1741124294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6CuZ/gppdjo5GNBW4cFCKjZu7BN7CD5DyBPM6OcMKTY=;
        b=OqxclxyvNuu3i1WlZ4JbDIAIqPzoGODo2B66FubLAm7LizMbFMmmmOjXi+HoS2Ly2x
         n2NdDCqnMiuoC3+nrAHfG9/lS4XNBMvJQx8qMtZCoHC1+vsU8rYVA+E6Y1IjpH0r8Bbd
         4wV4RGY/4yIjyalsU5d9xMpg+mOk4SdaT/cibPASvzDWxCcGqEoP3WNoP6PuE2wY9Z5x
         WqYo0hYkIAmkF63nLnbSDVZ+SdSwFzrbvw2qEJcoeKElZdRhVmdhJ+pQQru+H7suNyXn
         ouKWwefCSOhu2n/6zlj4S8pcOfna9fcWaKrd8TLqp745Gxw0aQLJkRHbYzHExK5RpI6X
         A5XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740519494; x=1741124294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6CuZ/gppdjo5GNBW4cFCKjZu7BN7CD5DyBPM6OcMKTY=;
        b=r9NL70OCJtTdC0RDhMtDfHu5rZEh1T2TSKLsTHP4tkjxphyyeZ35odvfwhl8qVD66H
         VXfgVkv9Z2LC07bs8gVjZ6dHKmORnRM6oHgXwo9WBCYSE8QLFe4m3FITVkFEQIiy09Ux
         iAEjM/5aBmAT1yj3RqjqBX0z1CGWUTyjWsHyzXMLlIkBhHR4jhiU7N0LaYJMySNdgxCi
         /PJ0hkmR3k/rgZdW0pPnzd+akppEkwkxtDyyD9fKVUA1pju8no6WHdilD/f1+JCTp2w0
         AWKysiBfIaVJMeibfR8bhK6gsqx77z5Ok0gEYyAL6YpgseJrPKPryDCcIy4vCq0dKf5n
         /WBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmT2Z6Aej1yCXmPKV3jXAaGC+NpY/VdNAk1rvO5Okji9YRSneMUFlWgBEzb8wL0VuHrwVbnA==@lfdr.de
X-Gm-Message-State: AOJu0Ywm2HRi009Gy9M0tTDsQazz8tVjx7Bk4JGQ/OS7CzCgiACDWcFq
	L8cYYZmCn8WSd8QBhNxx02Y0/vKXDLuQxqXTS0jY/CVulRV3S+0n
X-Google-Smtp-Source: AGHT+IHYsJyZvwX0LeOdgQAX9cojc5jdp1cYvQe0EEEVvQGZqGzYmMLSpeXQEcRt0fJELV55MK+3jw==
X-Received: by 2002:a05:6512:1245:b0:545:285f:cd7f with SMTP id 2adb3069b0e04-5493c56ed82mr845107e87.14.1740519492658;
        Tue, 25 Feb 2025 13:38:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGE88YKI0zwL3magadVx/csnDooV0EmgR6BRIDbcGno1g==
Received: by 2002:a05:6512:1285:b0:548:2a33:9bd1 with SMTP id
 2adb3069b0e04-5493c9e85c8ls87989e87.2.-pod-prod-09-eu; Tue, 25 Feb 2025
 13:38:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX4jg9hWnTjJoLbERZIr/yPd7GN1Smh9f+06upUPGoCWiwk3cwpETRpKDlnJj+xCjprUHYGr0hsx6g=@googlegroups.com
X-Received: by 2002:a05:6512:3f07:b0:545:a1a:556b with SMTP id 2adb3069b0e04-5493c373156mr1003336e87.0.1740519490188;
        Tue, 25 Feb 2025 13:38:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740519490; cv=none;
        d=google.com; s=arc-20240605;
        b=FugGlP3QwD8bGZ/9a774Z7A4eoTISxEA4SQY1IlWkzsy5QpnItbhaLIzAKjAwl4JUj
         xDF+lF9RcSj9f+0rIynWmg0uF/eRKGDbSrSJMjMtJbnX8NIDYRxAcxAGdOJ4T0Pp3xhR
         jn5vk47uMa++cXf7QIw9kkOmsQ28XygSTdcu4UiULYhEFj2OqA1962w7R0WtBMxIhWwb
         dtyVySA9vu5KZ9CWejf9M7Vi479uRf2vHQbPDjei1j3YPS0bgrO7IB9B9PbGWUjg1f2Y
         9CkPkqz4h0puy44otElg/nVnXcVHJP4WBWtVtf7S0HR1pK2hv5Hi9sVuBdjmtRz9NKjY
         nCCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aE8YFaAaS3yuOPewtHTX+TYTLUQYvdlxC6/LkkaX3Es=;
        fh=/Q9/cfcGcStnQkXr2hsaPkqawASsChDgEfbd1GlF88s=;
        b=lDp+SkOHEHoSO4xzP736Tjd6pp/bj+0tul/1BorAhtrqK4bpwwgriK9hGnhWBIyAw4
         mz/6ra8b1H+SyB425BWOMp0nwFVF3pGCsApEs4LDmSWBJWsOkQYgW7xk2pmyN7Dg6DE3
         2uC5RayHyIHW1Jb4WfajUNseJNS/FFvI/Jm7laIyl2jeKJ2b9xXrfnRlLYOPs4OQp1Nr
         MavsTBrDNFrnMPrPK/R1J5s079Ab1PFY9a89xk05AnDWvr/LexSQmeuIRMjmB8LyO63Q
         i1PnQsP8MvkUA1MTA09KbGpvYvxRFFBPWGTGa0MID075MMAjY4Pg6gn3sZt79MWmC25X
         OQEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T8bmA6V3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-548514f3303si140290e87.8.2025.02.25.13.38.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2025 13:38:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-38f406e9f80so5607831f8f.2
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2025 13:38:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV6ye3DG5dr8KoFt4FVTKX/8e4Wl7gTHbOHM78RSwSaOAF8EhZa5XiJqZvHm8K2mcFKQE0gnzUEwjQ=@googlegroups.com
X-Gm-Gg: ASbGncsnFAojZvq38QJNQv8KVcEEkhdbcVBC2RLyISSoYp63KUUGeXu9WvXzEs+BRFi
	3R7iu88x9yPkQ2ysolCDJwJDvQVKn8Wa2R1IP9v+pChPpJB/zhGNF4CRPKdZfHkgJSmHp1rvYkx
	Ea3VgPIR+Z
X-Received: by 2002:a05:6000:c2:b0:38f:2401:a6a6 with SMTP id
 ffacd0b85a97d-390d4f3cb3cmr437434f8f.12.1740519489416; Tue, 25 Feb 2025
 13:38:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com> <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
In-Reply-To: <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 25 Feb 2025 22:37:58 +0100
X-Gm-Features: AWEUYZnS8GVd3ERRXhXkc6hjvKnRC5lEIY-bHuz7PF3TjilwVr_-TxB6baR4YG8
Message-ID: <CA+fCnZfb_cF1gbASZsi6Th_zDwXqu4KMtRUDxbsyfnyCfyUGfQ@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=T8bmA6V3;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435
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

On Tue, Feb 25, 2025 at 6:21=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >> I wanted to have the shadow memory boundries aligned properly, to not =
waste page
> >> table entries, so the memory map is more straight forward. This patch =
helps with
> >> that, I don't think it would have worked without it.
> >
> >Ok, I see - let's add this info into the commit message then.
>
> Sure, but if you like the 0xffeffc0000000000 offset I'll just drop this p=
art.

Sure, assuming it works, I like this address :) But to be fair, I like
any fixed address better than using a runtime const, just to avoid the
complexity.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfb_cF1gbASZsi6Th_zDwXqu4KMtRUDxbsyfnyCfyUGfQ%40mail.gmail.com.
