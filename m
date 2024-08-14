Return-Path: <kasan-dev+bncBDTMJ55N44FBB56J6O2QMGQEWX7OWVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B0A449520B8
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 19:10:17 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-530db30018asf51642e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:10:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723655417; cv=pass;
        d=google.com; s=arc-20160816;
        b=x8y4YMidP1cr9iiYhSu+xRh883cnJaqIQZaMYJIFnoCA7xsujNs2Tr7o8U5b0o85Ay
         /o76nohnWNRQJX21HPOymIyG1zxFEJK6ED+c3cCMGTDUh3qHKsaZMoa6OEOxEIZFm5CR
         MgWcpzRwcGcs38FPLlySQOkAq+vqy/qfj4ztWRrJ/Oxl18q9kQ2UtU/kRxFiWCiRGf5i
         3ywwy6WzSctf2PsO3tIgPngv/irU5L52lX3nb3W72HF0ubCZ7D98+xDIhLBEVJ5yeEVl
         26sBi5QpgMz9zy0bh8e8lB61CXHHoxufzQgHEmWOLaD6XT8OOdy0J/SjOT/rickE2Qkp
         xx+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=LAwYkwM3Hp0aP22bY5CbD3mCWLGWeVOXGFjy1+KvdSE=;
        fh=PdFpY57qg1I/aV0T/KxZRCMQiTjGhq06kihOz4TrGfs=;
        b=wXQgR5K1pqAbGo5W/dMyqmc9qUN9cpdyDw6gOQj9H70w4z5GUgqq26aqhZXXUG/yIS
         ZzQxM+8QaJLLx7BA1zYYUbks0GbKXDv2cZsHaqKIL2nVM7hnsBRxQi1cBbBDpWhFx9Sf
         ybMkFpArDVLT4Yjudgnb7j30g+E/xwYQ3mg+hw2LVivgHiTyYXET8oDQUxw0SyuzXVWP
         Sb6pyMHgM7wpdisA3Ai1Rh26J/ytpoueAGL7ET6zXFHTs2GMNDry7wSlp/H6Xpu23oC3
         9MUSZoYNKVq4lTbRICu0KIkPFKbu/rDnAxk+UkPgIPYFkWgK730K9wuRmP2sHC7rK//b
         XmfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.170 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723655417; x=1724260217; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LAwYkwM3Hp0aP22bY5CbD3mCWLGWeVOXGFjy1+KvdSE=;
        b=u9KgYU3mvHGhnDxOC+oU5g4r2/3iCLwyPw4hfjsrrO0j6Mb5skUZQl3ppO4T2E9Xi6
         XGA99TdSdVcSRw5Rz1MVbuzKv6kCSIlK0+hqIl2CNk19GyFRJqzZdP1TC8JA795t5+BP
         kL4709kCX1KnlL6QeioJZscOFwZmfApla2Jn1P1sqWoRlXqajXLPglbdukEdXW8HoSw5
         ZnuTZq+1o/OBPAFyTdb8vpk+jxZDH+T/AbrtC12zoe8Q1izZJ29ttHqeKHshlDNQT+4g
         3TdyrXH9+pMHf3AJWoDps8rO8/7RU6+B3orVuiyNBCI8bQlc/UkZLBv0sWxyUd/LWcwk
         EM9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723655417; x=1724260217;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LAwYkwM3Hp0aP22bY5CbD3mCWLGWeVOXGFjy1+KvdSE=;
        b=cyRGWXgTdoV38tRfvYF+Bvy+226BG8g7jAHnB4qVL4mS6CBERvfQuv+dhgK44hjOPC
         qKwcE3e/f6XGoTKzkHmRe5zIT21ciCw7CiPAKb+AoVUtPs1fUYffbcu3GWwCDRWf1S7w
         o8dkSqMUR9UdZOlWzhIfYGLX8kbCy4yVdV05K1n9oAj5nFcknFZ2asMPz/RNn+swucU1
         kD0ca7LS07oAv80llOfvZ1PR1ZvNoEI96VZaWS6FbS/rIH8QriFeb2F1sy15WuoC1liA
         MlNY10SpK/RRC5TJtl8vEa0xa3MzCLWJn566qs3PJ2S/a/dojgpIdlg/iVCMlYhCngqS
         bHdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXgYym0j3jTJNxw5X/Sy6TOwyVab5t1C6+Zw4Gu5cgw2YUnLUZ95K8Ku3qJSmME3M3aVCSCyP+AFr7tAN+60AsNsodq64MKQ==
X-Gm-Message-State: AOJu0YznuhKtzdoJXfJp72Rr7L9sasax+XNT/Ft9U1YM1aQRGDe+soEL
	KC4gtDCCZxyRdUimaf1+vlCzMNVleyz99f5KQCU7j5FPOrhWMZKW
X-Google-Smtp-Source: AGHT+IHxRiYZEexM6dujrZ+WXYacbeybsjXYsoA0DkX+OmkYMWi9Fgrz97v3vzWwBptYQ1HiQNINSw==
X-Received: by 2002:a05:6512:3e01:b0:52f:c13f:23d2 with SMTP id 2adb3069b0e04-532eda871c4mr2566703e87.25.1723655416066;
        Wed, 14 Aug 2024 10:10:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ea8:b0:52e:6db8:304a with SMTP id
 2adb3069b0e04-53307d3880cls56444e87.1.-pod-prod-09-eu; Wed, 14 Aug 2024
 10:10:14 -0700 (PDT)
X-Received: by 2002:a05:6512:3c8a:b0:52f:2adf:d445 with SMTP id 2adb3069b0e04-532edbade41mr2275474e87.41.1723655413593;
        Wed, 14 Aug 2024 10:10:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723655413; cv=none;
        d=google.com; s=arc-20160816;
        b=qOH789VDNTl7GaKjVkXrgw3V+LpLVVWfwncNfHlRqONfoZs3bX1Ktzcuq+wnviXF5Z
         y73Un/ROZacziUVAVevJtZotVwolH1Z3B5nLk+YZ4J3t/YZJad1orCUM5QcajRdgELNz
         SHVBVZ4iGUMFFir/mT/5hOliI021a/ch1AjLksT/kXOQH9+fvW7ceTTo0Ys6kZwUzgUi
         uVP4nFhNnCTeXAU+0D2QUMhyxpwMirEgPE5zujc1HacLOOzW+sM5CtmDEiZAukzrrS5s
         8mFI/3k6kkR1PTxSImBNmZotdZf0uBV/iGDx4rACEvUupmRT3fphiejWnw5LFPlWRBn7
         4Yzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date;
        bh=7sP0prdJ764zDRhGrMOxeD1PYZLi3P8WVzp9dTBreHs=;
        fh=xpBT/2eWkbAlk/axnqkchZGCV5araA9Qaf1qmn1iP8Y=;
        b=VrKjEDpr1a0yyYx9W2qOB3J2i+Yt/Vuvo7tWKCBC3upPtUCcaeKYycsy3U1QKkcL50
         bkO0r3CCr3OZhtbN3VHWLW/63jSQ/TzOL0A4woo3JiUQLCVrP6PyBG88RK5EI/RIzZT2
         AMxaSm8/xWcpS7C3P6pPPiZT6/nv9YH1IHStHMd8kZyxUyFUNm3R8Qs+zzGVIXxlytmv
         Y0F5VeSlOZOY7YA45vnOHb9nVk5cvQaiNGCETHyamZp9/hJqo6CLLiMSrsQBADAVJynX
         Evo5oK78wDwkG6G+v9XzjJRBGj9An2e1+MD6adBiG7qQ8MtaPhVetmCjn1zHY7LAlhDr
         R4+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.170 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-lj1-f170.google.com (mail-lj1-f170.google.com. [209.85.208.170])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200ea4d92si225561e87.5.2024.08.14.10.10.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 10:10:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.170 as permitted sender) client-ip=209.85.208.170;
Received: by mail-lj1-f170.google.com with SMTP id 38308e7fff4ca-2ef27bfd15bso1481081fa.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 10:10:13 -0700 (PDT)
X-Received: by 2002:a2e:a99f:0:b0:2ee:7dfe:d99c with SMTP id 38308e7fff4ca-2f3aa1f51a3mr23695561fa.31.1723655412783;
        Wed, 14 Aug 2024 10:10:12 -0700 (PDT)
Received: from gmail.com (fwdproxy-lla-007.fbsv.net. [2a03:2880:30ff:7::face:b00c])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5be9bb73800sm1569528a12.38.2024.08.14.10.10.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 10:10:12 -0700 (PDT)
Date: Wed, 14 Aug 2024 10:10:10 -0700
From: Breno Leitao <leitao@debian.org>
To: kees@kernel.org, elver@google.com, andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com
Cc: kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	axboe@kernel.dk, asml.silence@gmail.com, netdev@vger.kernel.org
Subject: UBSAN: annotation to skip sanitization in variable that will wrap
Message-ID: <Zrzk8hilADAj+QTg@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.208.170 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

Hello,

I am seeing some signed-integer-overflow in percpu reference counters.

	UBSAN: signed-integer-overflow in ./arch/arm64/include/asm/atomic_lse.h:204:1
	-9223372036854775808 - 1 cannot be represented in type 's64' (aka 'long long')
	Call trace:

	 handle_overflow
	 __ubsan_handle_sub_overflow
	 percpu_ref_put_many
	 css_put
	 cgroup_sk_free
	 __sk_destruct
	 __sk_free
	 sk_free
	 unix_release_sock
	 unix_release
	 sock_close

This overflow is probably happening in percpu_ref->percpu_ref_data->count.

Looking at the code documentation, it seems that overflows are fine in
per-cpu values. The lib/percpu-refcount.c code comment says:

 * Note that the counter on a particular cpu can (and will) wrap - this
 * is fine, when we go to shutdown the percpu counters will all sum to
 * the correct value

Is there a way to annotate the code to tell UBSAN that this overflow is
expected and it shouldn't be reported?

Thanks
--breno

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zrzk8hilADAj%2BQTg%40gmail.com.
