Return-Path: <kasan-dev+bncBCAP7WGUVIKBB7535GXQMGQEBECI3MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F324880A38
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 04:54:41 +0100 (CET)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-60f9d800a29sf76942797b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 20:54:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710906880; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJo0suaYnWLYdzMzpNQCm5SKL+KmXYr1vV7+DGRtNiA0PKVM065AeseybaT0/0c+FD
         AvLKuUsoNF5SaqmrHJEGZw6V9Rjrz+bkMJ0/40BNq1SaELw1WkmszlEQlpRxR7W+a9P+
         Kzz1zv/aN7W7phJJPkkehxBYjQOxNz+TPw67kHh2Gya9bHm8KGyx5m6JwP7Rea5uGr0X
         4a+0JuZmwfY1IyiQbI9jdKlOfaAvbgxQ/DLM1SZbHwjg4rheZfK9DJ1KcBWnMWPaUn+j
         riXgNONiOA6CJuafphunB1CdlyIYAy4xZH6+lq7mE3VtYULvrshncOKVWH4EJVEvmyOJ
         PB3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=swUDXytp/9BbfeCUMo7/ksO9cC3jrAP+LzDCcnDKHVg=;
        fh=VcejKfhYmePvd8m1N2Ww0MINnnv55cQdJ+1+DQ9qzKk=;
        b=p1VdFkfj8L6UQENgC/3ac8AqLMyCvNZsoQfmxiKo6ngQqDEqVB9TSM+bVbWcfqsGSz
         vOD7PFSEMjyDWchLPnFTdeDtMIiBGMYGTU0axXERTu4hWV3YP6RJYwmM3SEF8IeElwzf
         9sQhbEhGsE0k9Mkmp4X38Fm05A0JiqPKk9Rk1zjJ3Xe63ZPL9guHk9TrookA/I3Ap7xr
         RPUg61ibtreI7XSihOGLadTnxJcrdCnBgSf0iulNZYunbmzIluIxkhBNGGvKjimBGPYf
         o1siKc6GVB3Ey18CnUO0pJU+nSmkWyMP4Zuh5jR1OZS/NxndPolszufhvfmLpgHhQYWF
         bFaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710906880; x=1711511680; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=swUDXytp/9BbfeCUMo7/ksO9cC3jrAP+LzDCcnDKHVg=;
        b=xOgYkXB2DUBFsdyqMUxHoFCzHP8jlkaT3VAxWa/rmna89xgAFECaSUCUHRs+NhiTUX
         68xRzTMBmIRKuvFF78rDJPeUXqJKiNBMRnok1XBJZT7F3/+U1YcNqDcYVI6oP2/sE92H
         vOnVB33j15weqG4CMWesJP7rzA0/p8zDr0olIe5cOBEX+ejyqsRXvRprZW3wxIaci6SZ
         5KqGZRKD68TGs9M3i8LXefr4VietdJdh2fvZdJjGBFT4hQmKsqYTM0+H4y0EP00VSABp
         JMfsWRegZ4feQsH6mstUJ6fn5tWcvOMOigDuQy7GQaZ6/5diTaq+V7O0zq+WzrY9xY5y
         395w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710906880; x=1711511680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=swUDXytp/9BbfeCUMo7/ksO9cC3jrAP+LzDCcnDKHVg=;
        b=p2nAU0ftRdrLcHu/VGhgnqsQU3ZKPqxHJ1wPeJwvid0hMeqKML1nP8LA0R4RL08lNr
         ESohWG6+kEA0WwmsW5UOkO7OqIwex0s5zH301k5fyV5BYhPbzNRmvDwE5Zlr1/F0TBHt
         lISdaGLmfx11QguOGosDiraNvtX/Mu+BnKiuFR4PJstLEJuMrnJwa+lIWQ+L998r1Zyd
         o0ED+wIqY3rCpI6uFJbmw4htjoSDVpcV9k6la668OiujNlCEYj9HUmOlrA4FSwrdBU9E
         MKwDQNAG5wpizBclowOmFA7ndx9RN24CEuSxsuLDfy6PiQVvNtQxjx7Gb2N46qK7pfQu
         KxYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVoLMB4W1PYR1xqG+0V6lZLVtaF9B/fuBP2EOGMcNzerNIBJfo1cesffhTgltO2gQMHsw2ZmW3CoYKHutX+JtwiAVgSI1B1XQ==
X-Gm-Message-State: AOJu0Yzg+xOSfAsDxZq7QpkbknmOh6lRKsQ2ySzdmworsI+23zoJ2R3D
	PMdfrYd13nm7IzaIjJ2egKKaemlqF1uXF55xcYTZgkZfhKA5cLH5
X-Google-Smtp-Source: AGHT+IGzd1xmi6x4gK4716SPMgpmdrXuOluTAb9WMfQupHGneaRmIpnnjDDT33suTBAGmXoZW4Xw3w==
X-Received: by 2002:a25:e812:0:b0:dcc:2da:e44e with SMTP id k18-20020a25e812000000b00dcc02dae44emr12850240ybd.61.1710906880246;
        Tue, 19 Mar 2024 20:54:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aaad:0:b0:dcc:f46b:129d with SMTP id t42-20020a25aaad000000b00dccf46b129dls977923ybi.2.-pod-prod-03-us;
 Tue, 19 Mar 2024 20:54:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoNhpIKWcJ+AHgNIBb2K9X+jzC2wGfH/3CGL3fOkpIFDXf4Ew9uABGltg9dxOpjijIfBS8zhyEeT09fufFCOc7XPaZMyJ1aPGdKw==
X-Received: by 2002:a81:5386:0:b0:610:c2a6:1b9e with SMTP id h128-20020a815386000000b00610c2a61b9emr7773806ywb.6.1710906879263;
        Tue, 19 Mar 2024 20:54:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710906879; cv=none;
        d=google.com; s=arc-20160816;
        b=NfIVFif5CBOTzOEZ2payhfPICdVgmWD27XAg19j+LiGK5Ak9A8urZphp7a+LpVt7XO
         +O6jHQfbcK3XRhtmTe7yEQwJPUJtaJWyksbQSKkSGOp8i1/ltuYAKui0pPLdEzbHlrOr
         XOS4taK//GInqfEvJPVL2TeK74pW1mYnFUKOX7KtKSP2URN0/5vvgyfGwK9AQqxLZJTT
         I34AxAt8p+jvZDgAmYS9f1DyXEVWxtv+1rmm611X49dbUgYx+AMuQyeoISxYPsEYoar4
         l1AZXssVvvypE69ee95yZXDBpCrzzf2pZDvlNgxxy2dvEO+qNM0EhqlT8gW2e0ch8I0j
         eaSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=Vu0qllrSTaldILjVSOjGSnlA0IHzjykL6/AK/t7rtt8=;
        fh=YOMzn9NX6AZYO62tpzrVyo4BFA4s8PWVuDKJ/HYfyTQ=;
        b=PorYb0evi7a1qoRPnZiOghep4f9UrJGBpBfkQR2EF2y1NQrsKyp4W9PRbYe5Z+x43r
         zI+Capa2b5YA9Yd4UrZ7pwWL8EKGuCEYdYKGzPgeSFpHJNpeIKu4deZX3SmWVU6sPiAv
         ROdzvfaX9qTEJ14VfveM6YUgHQaF3N00nngASkHoMx4ebScDhHeQYjKgoDeo2krnbZBv
         IYs3+Y/9s9FMYUoc+1xPsOOtslIuCfjIm37OBaxc44PEW1fUJMXhyelzDHrTVwofxLcq
         Chw4rDvIFbJvqMrvZXk49SPGgbqt//izdm+h5oA82Txl2jMK2JU06/uUK1EFllXR8V5y
         hVYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id f10-20020a05622a1a0a00b00430eec15a25si183811qtb.5.2024.03.19.20.54.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Mar 2024 20:54:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav413.sakura.ne.jp (fsav413.sakura.ne.jp [133.242.250.112])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 42K3sPLu062256;
	Wed, 20 Mar 2024 12:54:26 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav413.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav413.sakura.ne.jp);
 Wed, 20 Mar 2024 12:54:25 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav413.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 42K3sPRp062253
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Wed, 20 Mar 2024 12:54:25 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <f9a8a442-0ff2-4da9-af4d-3d0e2805c4a7@I-love.SAKURA.ne.jp>
Date: Wed, 20 Mar 2024 12:54:25 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 3/3] x86: call instrumentation hooks from copy_mc.c
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, tglx@linutronix.de, x86@kernel.org,
        Linus Torvalds <torvalds@linux-foundation.org>,
        Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>
References: <20240319163656.2100766-1-glider@google.com>
 <20240319163656.2100766-3-glider@google.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <20240319163656.2100766-3-glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2024/03/20 1:36, Alexander Potapenko wrote:
> @@ -61,10 +62,20 @@ unsigned long copy_mc_enhanced_fast_string(void *dst, const void *src, unsigned
>   */
>  unsigned long __must_check copy_mc_to_kernel(void *dst, const void *src, unsigned len)
>  {
> -	if (copy_mc_fragile_enabled)
> -		return copy_mc_fragile(dst, src, len);
> -	if (static_cpu_has(X86_FEATURE_ERMS))
> -		return copy_mc_enhanced_fast_string(dst, src, len);
> +	unsigned long ret;
> +
> +	if (copy_mc_fragile_enabled) {
> +		instrument_memcpy_before(dst, src, len);

I feel that instrument_memcpy_before() needs to be called *after*
copy_mc_fragile() etc. , for we can't predict how many bytes will
copy_mc_fragile() etc. actually copy.

> +		ret = copy_mc_fragile(dst, src, len);
> +		instrument_memcpy_after(dst, src, len, ret);
> +		return ret;
> +	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f9a8a442-0ff2-4da9-af4d-3d0e2805c4a7%40I-love.SAKURA.ne.jp.
