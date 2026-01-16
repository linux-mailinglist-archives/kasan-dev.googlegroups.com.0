Return-Path: <kasan-dev+bncBCSL7B6LWYHBBXX4VDFQMGQEGPCMP6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C235D31E4C
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 14:34:23 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-432db1a9589sf1568711f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 05:34:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768570463; cv=pass;
        d=google.com; s=arc-20240605;
        b=QUTI697H4FqaVV+T5s7wPH5tGhEQIQPYn0UWcHDZKYnFSEZR1kD2gv2LflkA8NpN7b
         hw0GfjLtcyyDLDaL1iug2Nd+6Gw2d04SojSG4mfqS246lLy0wsbuAsFmJuqdXxe2IqEX
         C9OIgTxyCIODFvs2Z2UZGnCkZWTHOADhmBNlOQLloHZH4BNZN4rWljaGEfr5fjY/pewG
         T0Z50hsXLTGjWbLKUJ8Iol/nZ+dmge3Z/RO8BTyUfez2ye6j+pqgMEX0b4iUqKDi3GRG
         UO5Hy478B4l19F+O/u1OFNClMUjKKhqpWwRM0HrhsuvexNFfb9jOaWTgHfwz0IRqcfkl
         jQSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=Du2J8soNUR22GG/EPeG8+DkNugu3IpIIPFXCxD15P/Q=;
        fh=aFCBJXsWuNrOlb73nWIOZnSheuxrIEtJexYt4WFNIR0=;
        b=WAf+06HEMh1EkcD49KLfJboFtGHtLKpMyKowSR6tA340jSr9wOPBkjcCar35Xa36AR
         7a+9oe0zQWuNyj0uVCU8mXFkXbB5th0GjNgrDK7Xxbhq8oI0QsSn5QzRJTTzX3wFIeon
         3Px0QaYExiQCikep73gQIPBv4I62kxVNVrfT7N7dUgjRsSQhNASkWKFG+DtsjrAIP7C3
         FUe5i2oHLrr1aVcgTHqs6LdT3VBDd/ul1jl/zLQubO6nNp+xlIq7RpP1t4CDzxql3Ewj
         ZFG+ZfyVYDO8YeDEzAejF2g9UZ2o/Pyg2qMpQrQakQKic2bWdpw08qWv+82wt09UScMD
         K3dw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZYkyPdKW;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768570463; x=1769175263; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Du2J8soNUR22GG/EPeG8+DkNugu3IpIIPFXCxD15P/Q=;
        b=XDmsi+ixisqLq8OOsxfCw7mVgqcry7HTCjm5BdpIvTWXsz4SXDDXGqkPZCGgXA5k+T
         MXw0PZ13HTfdqMxPYb7LvdUm2ee+UE73DTvqrKidowYgCH45LHSc4SRCYtHRUpqvc/rY
         aZedwhq+QQLTgL8RcOEZbZ6XIK4hpkmYKIlCo5VW/EmWUXcGybHXDwyjis08lQoALP9D
         M3eIdsXKovpGe5Ag3/wL25R+HvNes2S6aY0NkBU+UKMXNGgQFZ/Mh1YsagxeY/wMo5zl
         avvHfFI/ZI82fDZ8Vbg2xxaZBwSzvFgnZAhcekYz5QpgOvApuNXL8gLOMcRb65VIQZ7u
         Pi+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768570463; x=1769175263; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Du2J8soNUR22GG/EPeG8+DkNugu3IpIIPFXCxD15P/Q=;
        b=LP+5wFECdySI92FqAw72a05h/VLTSnVvvJHmGZgY5cXfVe+sERxxzvKkOHJimwbhzW
         DsRwyIFPrTFgLaEOGKMz7cPM+Ol4uViobor5XgC797J4anxKskPjo306EPR6hY3+6idr
         BdsT3ed9cwcYh8rAhbGqtYXJ2TWrG74pvFqDY1aieUBKf5iC8estestO/SZRRr3ULPil
         0vu3ilr5sq8Q7VX37vkJPtPyEWKvmhbevsQ6t0/cmifLtGrRRFBu7h7RvIpKxPQeiNYI
         Uah9tAWHnFZmFSIOXDio6cxpi8TCod35t35VwnJ9NAgNQFCnlrwdWTWsMpMBaxfE0Clw
         UFjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768570463; x=1769175263;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Du2J8soNUR22GG/EPeG8+DkNugu3IpIIPFXCxD15P/Q=;
        b=bZs9wx8engT3H0DNlJoYvsm6+dKDpQFybMtb37WMLpC5iGmTi6UAs9wIq0jh/9z5d8
         eBQ3OEvA04v0tIqYZZzR1cOuRMNqWKM1ltDhSq0HQYZ/DK5e5QN/SUOg33jat5mgeqsm
         mJZj4jW2uyhs/TvrufH1yTSiCVBUA+BUt8il7uLfwxuDJ/cojaResRPoQW85mXMm9mJd
         aJnCkZ4bkrPgK203F1Itl2AKezUtTLIOKoN6mD7aK4EEXk4UuTUS+aWBVloGu96EuEMK
         yoTySLNteP6Qgs1mWNfwZHX2ePXkUct0g0FvJqlW5KpzKxwCfG1CZb3UQNGvcW15WNGC
         oJxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJDnPAoFaiSxN5COZomTNGPq8wy6Qt7Fx8pGABbZUP+a5PpFyEbtjz93qqHJEttZLXKm3ZCA==@lfdr.de
X-Gm-Message-State: AOJu0YzKTBEW6LFbeTAJNuIsBU1oGS9idpf3niElM2UNpSEAzbAoFYk1
	O1a/WNgC4eVh09OzxIJWbmuB0olLUl8hJDeCVhXVGj1JtYgmjh6Tat+3
X-Received: by 2002:a05:6000:2012:b0:430:fd0f:28ff with SMTP id ffacd0b85a97d-4356998c0d8mr4072555f8f.26.1768570462778;
        Fri, 16 Jan 2026 05:34:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GecK6xigDUTbkyiT3kCZOrMjyda9gurLKFotkV7+iR/A=="
Received: by 2002:a05:6000:2484:b0:432:dbd4:cace with SMTP id
 ffacd0b85a97d-4356416d6fbls1266034f8f.1.-pod-prod-08-eu; Fri, 16 Jan 2026
 05:34:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUaWeW1Rs5UjrH7ZQXj9UGATuNM3PUnK4K6YCR7kcb32o7IIEPngiXx9ZCf6kim6yMMS4nZH0kQQe0=@googlegroups.com
X-Received: by 2002:a5d:5d89:0:b0:42b:2ac7:7942 with SMTP id ffacd0b85a97d-43569972ec5mr4096825f8f.5.1768570460379;
        Fri, 16 Jan 2026 05:34:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768570460; cv=none;
        d=google.com; s=arc-20240605;
        b=T8/EgbqQ1+levZ7kN9kGAFLJULh4q62X3vvYllV/Dw/g9PhQJjstOMiXUMq8V8bwRU
         MrnRmA/J2nwDRgJ2UzPVQrf8/AuorSjEoQrtDH/vq+7REHZ1DffG2dVfbCxJNOiI/UFU
         k4ADtYzXu9d0qYWbWvK3xFjBGkaGAg8GGqLy0Ht/mKKHHUM/z1+9ii8Tav02exaYZUc2
         79ttLfQEY4DKsXqcBaiFmSlrqEUXSol61pYLf2Nob6acNdHJ8piHGofQRzX3tHdSNYFT
         WDAQOxc+WDtt1KaRLfFzJV2NdwxnASUg9aeNisA2ymbOzITpKnKsu8HgwgUQDafLDPW3
         yaDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=bev0/5BsocMDQdsWbP6nwDXNzQ2lVeqE+NGh6GYspu8=;
        fh=Qbo6MRSidm/6osR7MweUFu/9av1UIqpN+dFE7DuX40c=;
        b=ZwB0Bjsf40j4rvK8yONiGcoQg5L6iSvSUGg5sk6MmNYaBV34F3zsmyexHRAbhoe6xq
         MembAH+CkQ2X6DrMIuLU6GeVXXt8lXlZWf9RwD2RSSyVjMD4wGexnXBexVuYj5d9PkUF
         yla1mgXYoNAiKrbTCMQ0rhn6QlQYCSe5erPHwfvqzWuLtc/gQPpExJ977ZWKD1Bn6ktf
         h3imNapN0r4dn6reNEEBRzkyHBLPgWNVyTVGvlDFjl5S/6qSnZ1qMfz5OMqRNK0AALQW
         sl2Lkrd00ZtxChX+6x6CdFliRYKV/zFFbFi1eMLYgw7daWTyh4fN6aJlyr6uK1pyyzI3
         2L8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZYkyPdKW;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-43569980373si44711f8f.10.2026.01.16.05.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:34:20 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id 38308e7fff4ca-383172fc700so912341fa.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 05:34:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVH02Emah/tOly6mFplIBrCh0UES2D9KUO1pRqg2F4aFa0gzX0ZfjFQ65y9AXQEmuyrwG/AF5/RS4A=@googlegroups.com
X-Gm-Gg: AY/fxX5ggsuj6z3pyoc6F43CIEdxzpbFTUYDIxYY3tro4zdNU5jOVuqm/esGy82eKd6
	T+LUolDJoXuPaLx6lnS6WRb2IFCWt40U6x8ynz1ANT+wPMMy842FYQJEjx3rwevx/DbLISb/2bH
	2k377zJYQsi96HbiQ7U2GklRpGKx8zhhJ2hTOU2ZMX8lHD4wPzoAYaZgPHv2miVnR9vNcXKH5sE
	SB590gqmU4HxNSZrZ52jJGZ8XVpaoFxle4fLF6xZvHHiqMn1AoB8fNzoEKcG4FgTv7f3IkTcs6D
	yHhb22wTDgT47UzZXcWK2UD+KJIBvM/HtiF32pB0VnivE9mkNVwQs/o1crYcnqqL0h37TvfIxTs
	/3309a2krM2/G7E3qI9ckXqfW596u99rCIEmr5+BnhJaWfhM2shs54xdvpj0kOlya0rYZrGMN8x
	DRJbuJl6wITHpAZlxiRQ==
X-Received: by 2002:a05:651c:31dc:b0:37f:c5ca:7428 with SMTP id 38308e7fff4ca-38383fe052dmr6437051fa.0.1768570459458;
        Fri, 16 Jan 2026 05:34:19 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-38384fb8ff0sm7244461fa.45.2026.01.16.05.34.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:34:18 -0800 (PST)
Message-ID: <1f821f5a-403b-4dad-b9d8-239c9b039000@gmail.com>
Date: Fri, 16 Jan 2026 14:33:33 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 03/14] kasan: Fix inline mode for x86 tag-based mode
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nsc@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 kasan-dev@googlegroups.com, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <1598e2bb7d45902fb0dc4d0d8e218f61b0c1a0f6.1768233085.git.m.wieczorretman@pm.me>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <1598e2bb7d45902fb0dc4d0d8e218f61b0c1a0f6.1768233085.git.m.wieczorretman@pm.me>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZYkyPdKW;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 1/12/26 6:27 PM, Maciej Wieczor-Retman wrote:
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> 
> The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
> inline or outline mode in tag-based KASAN. If zeroed, it means the
> instrumentation implementation will be pasted into each relevant
> location along with KASAN related constants during compilation. If set
> to one all function instrumentation will be done with function calls
> instead.
> 
> The default hwasan-instrument-with-calls value for the x86 architecture
> in the compiler is "1", which is not true for other architectures.
> Because of this, enabling inline mode in software tag-based KASAN
> doesn't work on x86 as the kernel script doesn't zero out the parameter
> and always sets up the outline mode.
> 
> Explicitly zero out hwasan-instrument-with-calls when enabling inline
> mode in tag-based KASAN.
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> ---

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1f821f5a-403b-4dad-b9d8-239c9b039000%40gmail.com.
