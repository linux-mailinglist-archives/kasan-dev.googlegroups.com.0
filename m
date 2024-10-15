Return-Path: <kasan-dev+bncBDAZZCVNSYPBB5WEXG4AMGQEHUL74HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5219F99E9FE
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 14:39:22 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-71e49bad8adsf2714576b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 05:39:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728995961; cv=pass;
        d=google.com; s=arc-20240605;
        b=FyvZSwz3JlvpHH4UdosmWmOspztiwnD6WgX/2d9uFI42beV40ocnxMBkCC+Zi13zBN
         WWKl8RH+lNlDm6oXiR/UEUSt11+/kZEzl6oPZPlI2CjJ41jfDjNVpZAuPWYgddryS9Jd
         fMWwRaq6SvYDgFiqAtmFFx1nXcFo0jKTE2P4zGUienainvhBFSSryWPMO+uwo0oKtsvO
         r8FQX1FXmxfzFIDxXESiArebOEs2LAk6eZKestVw2Z+hITJXON2MntsEK1MUr+q9juUz
         8pfecPN0QR6oX3aBLDWs+vGrjaSV4ZfkHoNVYSP9Dcc+6xOIFRYgt7xZKstRqNh1yblh
         PclQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+/AwvjzRVHCK34wcXgn8YF7mFa6vPRg8Z1rsBFoz/aw=;
        fh=03JOKlzCOQ2go9PiQbBumlTvZxIQIm14Lcr3VflNJV0=;
        b=j9n292nGcYGYiXPM354TAMyTWK82UazkBRYfipyCH9/QJenD25fK6rePX9I4ipobMK
         sfy4VCB9bkg6/Jv+3LUN6VvlmRz8Lp4JVEj/s6HcV8KPfowBpeC92BxWqvlR0LuykQjQ
         c+EeiockmhcYRlnZN7hyVbyXKMkeU0UrHMODXhpqlmR31yADVI1QAiqbJ4jmCIByE/zz
         q1HKGru/yr4+rySwKROKl8o3LFomBxNoSO5gXDm67JsTx3UI2xH6Ifkop5dyxZ/SeLRE
         kOEp9dmdctr8acgfr8kXHqUzxCkHjNGmrx7uOLLy+qq/na6yeB34WBJT3lOCutgg70kS
         5Yiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JwV3hPt4;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728995961; x=1729600761; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+/AwvjzRVHCK34wcXgn8YF7mFa6vPRg8Z1rsBFoz/aw=;
        b=NZzmZJfjiunBjje9BIzg5A+k/sG3PKB5q/yhm4hSYzr3MEiM5g66h8SMyYDmVqQhc/
         Iozj0B926avn2VM56bdGuouGCVpHGrcAGZa/wfu7IXDKKq7vaHx/iktouelF0+BjUNVu
         fvFaK0LFWzMGX5Hk0bvSFCwhOG22F//fdEPpPw5CP06t8mtk17lM4qNd9Pr0qM1owrBU
         8TFwtoOdKwJRkIBZCFDZEnSECoY2x0C4cRZ/gzPaskl/AjYMSJHNx6iaIX9wiPToYhsN
         GydFvGiKeE9dTkQbMT4awzaubmOFP5LT1S17jATlEPeQlX5HjiZFglBIjYI00mhikvPH
         aUAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728995961; x=1729600761;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+/AwvjzRVHCK34wcXgn8YF7mFa6vPRg8Z1rsBFoz/aw=;
        b=FvOJsil9Umcmnok8rA4NVN0uiCCMsoKov+7AALNZVE6D9yfNQA21ObV2/wzOilJ+2g
         Vlf6ZWAAkJwymovmxhozDTj4UlLH6p+MsqHVh6PhJ0BldUj7MIbnPdlQEfcq8k9m5qHl
         2m08p3aZTk003Jn2OjrsPn0hmJuVqK9Fh/iBVunkEHjEqUrgKGuqsyI8FZI0OCG28cop
         yi64B5A+0f4+y0XCQ43HZQOqtswBgnPAf1HBnYyutLuAamlvX0EVzF0Fgae9VjHcb+DO
         UUw8r/obmPZYShwCIvqwWO8rUFQ776RnONzGSA/d7LSj0ESLdkjg/WufNJolILgg3M0R
         G2uA==
X-Forwarded-Encrypted: i=2; AJvYcCVvUIf15D2fzjfvjsK19mu5kRXPx14XIbxz4YuraE3QkxdoTIHqmzKicTMYfK5R1hciAXAzyw==@lfdr.de
X-Gm-Message-State: AOJu0YxFrHL1HHGQDjk325bFWvcUDkpHJMEFc1Z/f0Bl0Nfn8KmaVFA3
	yjVJmJd8eW8sPLH1twMdVm8H+Y5I2zvONeovOhk9FmF8UrmJ6PtB
X-Google-Smtp-Source: AGHT+IFG3IOZtPSb9/Z5piOJU+JJt0Su+oLnR0QYEDNST5CWlov+b00FW5qVOrWLo7c85BJn+GWx8g==
X-Received: by 2002:a05:6a20:d48b:b0:1d8:f97e:b402 with SMTP id adf61e73a8af0-1d8f97eb71emr2413268637.13.1728995959197;
        Tue, 15 Oct 2024 05:39:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:21cd:b0:71e:6198:3294 with SMTP id
 d2e1a72fcca58-71e61983bdfls1521657b3a.1.-pod-prod-00-us; Tue, 15 Oct 2024
 05:39:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5/JwUb/2mEzGR6Ze1AvHIc1gmtR5SwQFuflnhiwq/Ulm6aw0ecagaJilyA3T3U4RAusbQ3sqwn24=@googlegroups.com
X-Received: by 2002:a05:6a00:2d8d:b0:71e:735f:692a with SMTP id d2e1a72fcca58-71e735f6997mr5587659b3a.14.1728995957809;
        Tue, 15 Oct 2024 05:39:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728995957; cv=none;
        d=google.com; s=arc-20240605;
        b=L02zy2+Qneh7xC9CqLjzHptWrLceU+LfyYhqrRevTa8rorusxvMQWOSRZbuMPfvuXt
         lMF1nSlTcVUdoOgIr+qbc3d06OYIN16F56GxfLuMxwscfx4CFd7+NEBby3/Z7HTaeW6J
         MxB5F9I2ElTvGtA5PxxCqEK9ai3bXwJK/U/hsAwEscw08BDD4L+1IDRCZJ3ts2TaMQRN
         ytHtZUfLtQRBPw96aNGEIhdFabNy8oaEoTlFU5hopqPDXn0wgWHDU0Epr77yJDlNeyNx
         Nshee25+cGIFW04t+O2KyVylTaxPuEPZpMG+kYpJ8GVaRY2YtywaJm0YIYkA5Z58Iaqk
         9Row==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CW0ZD8Did1c4BUxvpyPs4HwsnU4pcIh+v+oOD+LqfX8=;
        fh=YRH2bA/IyuQz3BM28wVkkTguvSzGYyY4EDTaaSbJrTI=;
        b=LnxSKeAV52+ZDkzYbXbBdIVJ0xXkm8XQqvTJJV7TSJawyhKkOSb/QTsug0kV5Q0dV6
         mSZg5Am7pG7xM5LfRRTdyuvaLPfwzhARF6h0BR4Mm+LdJI/5QQe68OHqnsjuXh2Av/J2
         yBPVMIXw/xSmK3pds41BYJDQZr9GODkTxveghXLXjuY2CGY2+VEp/AZ9XBeV8lyq+SlM
         kneNspBYCtjoWgFWMDvOYR0j1sar1vRv3JJ0mNOhRxNfw6iH03XfyWMdCNCr4dUCHKux
         tZqjojWv2WW+TXYmgX/71Oq/bdlnebzVzZ7YCNsGkbec8TWf/sfBT2pDdPOJ5u9eJK64
         ISXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JwV3hPt4;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71e7749a6b2si60110b3a.2.2024.10.15.05.39.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Oct 2024 05:39:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D89FAA4259E;
	Tue, 15 Oct 2024 12:39:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 683A1C4CEC6;
	Tue, 15 Oct 2024 12:39:14 +0000 (UTC)
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-arm-kernel@lists.infradead.org,
	Will Deacon <will@kernel.org>
Cc: catalin.marinas@arm.com,
	kernel-team@android.com,
	linux-kernel@vger.kernel.org,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com
Subject: Re: [PATCH] kasan: Disable Software Tag-Based KASAN with GCC
Date: Tue, 15 Oct 2024 13:39:08 +0100
Message-Id: <172898869113.658437.16326042568646594201.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20241014161100.18034-1-will@kernel.org>
References: <20241014161100.18034-1-will@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JwV3hPt4;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Mon, 14 Oct 2024 17:11:00 +0100, Will Deacon wrote:
> Syzbot reports a KASAN failure early during boot on arm64 when building
> with GCC 12.2.0 and using the Software Tag-Based KASAN mode:
> 
>   | BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
>   | BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
>   | Write of size 4 at addr 03ff800086867e00 by task swapper/0
>   | Pointer tag: [03], memory tag: [fe]
> 
> [...]

Applied to arm64 (for-next/fixes), thanks!

[1/1] kasan: Disable Software Tag-Based KASAN with GCC
      https://git.kernel.org/arm64/c/7aed6a2c51ff

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/172898869113.658437.16326042568646594201.b4-ty%40kernel.org.
