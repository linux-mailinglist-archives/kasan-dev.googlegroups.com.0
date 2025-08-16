Return-Path: <kasan-dev+bncBDW2JDUY5AORBDE4QDCQMGQEQCJFMAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F4DAB28A94
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Aug 2025 06:50:22 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-55ce52874fcsf1433530e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 21:50:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755319821; cv=pass;
        d=google.com; s=arc-20240605;
        b=bPMJOBfTROa6mjMCYUmXhOnUd4cjbvaKRZCG62dTnBak0QH2pZ/w9IQljWriCfFVWH
         cChXh/90xEfDlA/P+WViiAvKfM9mQUpzQZbYpfT96nrkLhCT2G//R5tQzrexRqdshjMK
         jNsl9Y4LbxDsWU6SqDOzP5zea1c12DN+9lyOZ0LFeLKXga54f/d0xmUqbdqBSd7Er0Qs
         gv/GDtRLBHQT+ZknQc4f18VSBOma0zTTk6gJ09PMngGlfx+cLBACy5iP7gktAMMh2DWh
         P3koJo4zxYXkN6ou72w2f67QrTrveJcJflEmXOy1rPmAJRMIxFVGR2VShjI7G03avhtk
         OTAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=2cv4eP+/rmcwjFa96tVaNtfumxBEcIwxbdFiD4LRq3U=;
        fh=uMgRsN3/OQM1edidpmv1pcAH+6PxvH55gXRzvUWe9f4=;
        b=hsolNbU1u0FFl8zbFNlGMc0gPQ1A62AQOOxhiyY9NhS3PEEg3xHAIKvoGzpS7b1jJf
         L0X7TZ7M37YaYzntnE/EcX72yJXf2LpuFySd1Ei3QTYiPymQvf63un5Y4seXdiggLOpL
         WWuMkVUiNKIBMJE+rdGDH+e8niv69gLOdTzbwYFIaV4UCi1vyG9/E6b1ZKnWbAkviatA
         H59xkrVSEI5UT298El6UZDzgleDGVLJd4jErLi1srEQoV2YCbipcZ6I5tARhwzR4dado
         lUXT3M/3FVHKPE+x+qt8Z9iDUzQZiGQvGt/VXvjWp6NHpa70DRURRQKDYYThHVflH1M8
         0VpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZpcItXoo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755319821; x=1755924621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2cv4eP+/rmcwjFa96tVaNtfumxBEcIwxbdFiD4LRq3U=;
        b=vaQ0f6v34uRw/d6O/fW6mqJWFwhrSg3ln98R4GOKcMSEycDwlrx1LCF5m9/8haDGk5
         RgWBoHHcT424XqazxQYNOvcEawv/EwTo71GV5LaE+aVjOTL5YrT0NH05WSJVSJqcyr0x
         4x2djXOY3hHDtVEMmjDuK44csYRzpR6N2OR6J5WomAAtj9k01aatLY/wFY6hB8mXXhc0
         uFv3yfmagZP1JZlAIvacu7j/XBjAfXK/3giykLkfgfQ0Rzta1WyRrbLpLdvb8lpwPpdk
         CxUySUUuByYjFLXJrPGZV/8NyqHcPnG6Mz2LTQZYZoom3dPH3jXY77yMfm+d67WTMCVq
         1f7w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755319821; x=1755924621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2cv4eP+/rmcwjFa96tVaNtfumxBEcIwxbdFiD4LRq3U=;
        b=c/IV+ScJ5p+JQrTKkUWlakvlz367zjVSRu1qIcygteQ2tE4ijzs2VplJEIckzuqzCS
         Xlz2EJ8WfaoX+dmESNkP1rvWGIi5ahdXyZg/QKC+AzwHNoi3oSPw8rz8tNHUnrmXRz1+
         kIB1O6wwsprNYC3U3tHx8naUUuZ6PLMfoxQNWMu4qa8PtoXTXZTEvfQJd4YIyWwYy9KY
         iyeb2AF/YQ5y8DCBhbMPXjjkfOhStr5ZVwdA6T9HLO/2M1pIcFbITmDvz/IgO0MwacXb
         kdjp7bXBnJzuoAU9J+GvoKrZrd6D7uYd3jLiXOkvdmQ/2eysv2GvSJwScKDujEEVmavn
         NQwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755319821; x=1755924621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2cv4eP+/rmcwjFa96tVaNtfumxBEcIwxbdFiD4LRq3U=;
        b=qnp8w8tDSRaKNKIcTecVWrPlbuqoy4yfHQXXZgpcmcUCxgKhRx9YetX9FMsQij9yUh
         0ndggFtrHs7h8jQ8EAERKAIr3qz1N7liE5AdbUdygB8yp7bXWDxuJ/0H2zxycXk5+nh+
         nMB2IXl0xmRPKGqLRfHUjzHb3/YMMoUopNiIrI8JtYA9VNrhaNdhGVTX4/UCRfn3Z7In
         h9ckdGYJbBpPo7ETZs5Q5szWsuRUtwcOBPU1fJinl+5UIPBClei2VYBwKIRvvhD1cE79
         2y5nUQlaIYjC6DDAdjIOu3zAMlgJzFvCiqZOSVI/FyA6INmVpDjZlf6O8G9/moP4oxiM
         BPPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU9ZDwKwDDKb6XhmtweklrCpfDa9gzdPlC45W0uabliLn8OHfxfPLnE9e71P/YpQc3MYzZuJg==@lfdr.de
X-Gm-Message-State: AOJu0Yx6RUavULtDMDrTbGxJ1XrOqWSN5KZoAodUynW4nlPeAIOIL0BB
	D9J9xp+M0mzVvHVZ13NZWRkDqOkl3VDRNxfaYXuvF7j7ssH/fO1HK+9r
X-Google-Smtp-Source: AGHT+IGzKbdaBNcd9sQkEgT5hUnVeWTSdZy2mESsmukHSYBX30GsQDv1pY5pcG2PSbA7Wr2sacjhqQ==
X-Received: by 2002:a2e:9b8e:0:b0:332:631e:42ff with SMTP id 38308e7fff4ca-3340980fd9bmr8692541fa.13.1755319820978;
        Fri, 15 Aug 2025 21:50:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcQhwk9ePzfgPLdfT/hgNZny/XtVTTY6iP9fozHzbbKqg==
Received: by 2002:a05:651c:4204:b0:333:cb55:f585 with SMTP id
 38308e7fff4ca-333f7aa6a05ls6701791fa.1.-pod-prod-02-eu; Fri, 15 Aug 2025
 21:50:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUEi5B9hgdW3fJte7b7CsqwekuKiz9nWLtfqUZVK5Uqc31hYX147wSnmUOqCxesQgd2vw2w0l5ksf4=@googlegroups.com
X-Received: by 2002:a05:651c:3255:20b0:32a:ec98:e15a with SMTP id 38308e7fff4ca-334099afc2emr9172981fa.36.1755319818201;
        Fri, 15 Aug 2025 21:50:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755319818; cv=none;
        d=google.com; s=arc-20240605;
        b=Qtrc0E5FF81z/ZMRKKBF9oPL0DqtPhALW0ir1wJLx3957pVjzW8oJlNJQM7kuHMTK1
         xbX7Xff9oBSOJdFLhpnu5gLqwI7efGlO8j/4dLRLEOQZgIYbW7vGSWg1RYSxIMmmSPvV
         NJ6UorjwAiryOsBOzmGzIy6ZJoaJVV/0vPx96t4F7Xxz4ulR+R2atGX4PDVtj4bbCA/F
         yVe35/UcJedItY/PU2rSDHb8rVSmTYS4kVhfP6MsMXjYEP058UanTzrm32i3Hc2g8E6I
         WTDIommwFtLofUr5j6rk2mAaOCuTwXkVgL7MdFrJAVVqmcpt4LKe06fmxnXyhFikgvPa
         87/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BNvSs17H30Pojr0mYh58UbN4qSdGEsmKv1b+WURr28o=;
        fh=ggb8baLUGCuGgGbT7vXYyw/uwxR+yatpU+XiYj3cTes=;
        b=XsOrezW5zm/ROdXjHgD7apuLZ9VBr7kFJh7BG15zl0SVbX0flFX9OGO8W7YYS1XVIj
         hkkdpJXUbKLA8XFEwMICo77TwJAaY1cuoQXwh6sPpPhNoCcRr6s3slbpCqYi0AWqlqM7
         qyyBeDNEo0ayvXLjoMMcqVMOLrJNvjza7roE11oPPjINhPZo6qmaEE35zU+uWOnHZakI
         QodmK/yAChzhHB99w8JBTDuSddwO08hH6G2UHSHga1Mi36jaxcuwEjmlF2OBVAAi46kX
         792MLXO1vPcjxEBHF6aw+d1u3L6TSidKRJ5laEI3Jd1UAjP4zJEXROQQ56iztfdPhU5V
         vDJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZpcItXoo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3340a4c305dsi653231fa.5.2025.08.15.21.50.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 21:50:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-3b9e415a68fso2318770f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 21:50:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXfhxyFTNqvAv0ieZZrYtmRtGfFkPBHEfBTt3gzk3P7zQn6qejdRGV+NkmbctGpn8ZFEg+2gn9PyPU=@googlegroups.com
X-Gm-Gg: ASbGnctdcll8noc23EkRdivkXuoCyG2lWtapbuZbXrlWS1/AOrWc9oSfaSxERww2SfC
	EFHslaXFtMyHifrf/OJo6L1MFPoTke4AV5w3cezyoUbyv/CtBms/NTRwB7gs8rdgbdWxQtcfQtt
	J83lEKPPtlZwl/cE9Mb3ZtCUU/wR1F7YyhOphyN8uEN2mkIOyIcfS3ozso+nrlONMasZ5vRCtS+
	A0fl69e
X-Received: by 2002:a05:6000:200e:b0:3b7:735f:25c9 with SMTP id
 ffacd0b85a97d-3bb67100411mr3698495f8f.21.1755319817249; Fri, 15 Aug 2025
 21:50:17 -0700 (PDT)
MIME-Version: 1.0
References: <20250812124941.69508-1-bhe@redhat.com> <CA+fCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2+NA@mail.gmail.com>
 <CA+fCnZdKy-AQr+L3w=gfaw9EnFvKd0Gz4LtAZciYDP_SiWrL2A@mail.gmail.com>
 <aJxzehJYKez5Q1v2@MiWiFi-R3L-srv> <CA+fCnZfv9sbHuRVy8G9QdbKaaeO-Vguf7b2Atc5WXEs+uJx0YQ@mail.gmail.com>
 <aJ2kpEVB4Anyyo/K@MiWiFi-R3L-srv>
In-Reply-To: <aJ2kpEVB4Anyyo/K@MiWiFi-R3L-srv>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 16 Aug 2025 06:50:06 +0200
X-Gm-Features: Ac12FXxYLTsqomvoG9UG93Lotus4fuW2rcu_NxDqALVSquB40p2BNceICCGi8q4
Message-ID: <CA+fCnZcdSDEZvRSxEnogBMCFg1f-PK7PKx0KB_1SA0saY6-21g@mail.gmail.com>
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	elver@google.com, snovitoll@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZpcItXoo;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Thu, Aug 14, 2025 at 10:56=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> Ah, I got what you mean. We probably are saying different things.
>
> In order to record memory content of a corrupted kernel, we need reserve
> a memory region during bootup of a normal kernel (usually called 1st
> kernel) via kernel parameter crashkernel=3DnMB in advance. Then load
> kernel into the crashkernel memory region, that means the region is not
> usable for 1st kernel. When 1st kernel collapsed, we stop the 1st kernel
> cpu/irq and warmly switch to the loaded kernel in the crashkernel memory
> region (usually called kdump kernel). In kdump kernel, it boots up and
> enable necessary features to read out the 1st kernel's memory content,
> we usually use user space tool like makeudmpfile to filter out unwanted
> memory content.
>
> So this patchset intends to disable KASAN to decrease the crashkernel
> meomry value because crashkernel is not usable for 1st kernel. As for
> shadow memory of 1st kernel, we need recognize it and filter it away
> in makedumpfile.

Ah, I see, thank you for the explanation!

So kdump kernel runs with the amount of RAM specified by crashkernel=3D.
And KASAN's shadow memory increases RAM usage, which means
crashkernel=3D needs to be set to a higher value for KASAN kernels. Is
my understanding of the problem correct?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcdSDEZvRSxEnogBMCFg1f-PK7PKx0KB_1SA0saY6-21g%40mail.gmail.com.
