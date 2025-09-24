Return-Path: <kasan-dev+bncBDZIFAMNOMINHYOPYYDBUBEP3JOZU@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 70A6EB9A05F
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 15:23:33 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-368348cf7d5sf26425991fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 06:23:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758720212; cv=pass;
        d=google.com; s=arc-20240605;
        b=bPiAAsQGv8anFnBI8UqaaHshjrNLmagPkJp2uQbd08uTVtCcHnP4neQ2vCLOgRxCJI
         X2mOrUKsfQzzdFn9eDqVh4Jkj7XZkKYkuaI0+UQ6xESYj+u+jRVxW7MZiuji6aQUGVEy
         yKTH1TurWCsMPSR6CLieQXOFDihg+dd55NA/TRGU560dkAKPBnvxaYHQ6XbLS1MiH6sh
         kda1JqIxdl2gqiHklGE4rC4lBdpRVD4p2Ql9dnKg86nicEnuQM2Dl6kSgYTK/nuOs3PR
         z3dnLLi7Hu8lzOitdrbN/MHvrH3sJLu/qrgqJMNc95a1spiMKqEcS6P4Qf6KTtuodLib
         GROA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:ui-outboundreport
         :content-transfer-encoding:in-reply-to:from:content-language:subject
         :references:cc:to:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=qDWS8q9JVPJXo6r4BwVYtaF46QM2Tt32VTFfLXjXSeM=;
        fh=L65gQ5d8uvcNpYiKVxz6fH9snKR38+bthenuShz+ejc=;
        b=F/eaCID5wlq3Qutqq13T437DNZf8REZGLOqr4ui9I/JnMffFp8kVGUruMBm4glQztz
         zxUTZ8SoNmwdPcuOpalzl0mUY1yCLs+xfcM6hqP46/8uM3/ALZYGdPeiNocvLgpjaStx
         C5mIpCpyE0/i7CNkGe0GO68TIyWZgAAWJSzVo4IlnqiqCuUgnJutZrxTSxRayDRZQ6az
         6/dx5picMCnbVGJWLZP1RWlCLQtBqR+3IkpKGKHz03Y5ZD9mz7+eW+p/CN+5uCK8WfOc
         09ZPDxhvNNktDY0m+sr3yrnHi0X1htxpeSyjpHnA5D8JTxPcdndxnu1HDgKBpI3Wz0Zh
         4xoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@web.de header.s=s29768273 header.b="Q//IkjTE";
       spf=pass (google.com: domain of markus.elfring@web.de designates 212.227.17.12 as permitted sender) smtp.mailfrom=Markus.Elfring@web.de;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758720212; x=1759325012; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :ui-outboundreport:content-transfer-encoding:in-reply-to:from
         :content-language:subject:references:cc:to:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=qDWS8q9JVPJXo6r4BwVYtaF46QM2Tt32VTFfLXjXSeM=;
        b=au73iyillpWvNJjyqcjFmHy+UQTLqakkRCb7uKtqVsrmDkPwaiXzJwcUM8riOXM9zI
         83Wb3HXDpUriE8fQAh59QZ5ixFh6HMDLB5zPo2ev2B4nwwfGrpe33zH7XaEJ6Z4SsVCP
         ui6T533KOYfr5utd8u99ZRF6qgoXmb52b1/Yxz/T53OgsaLY5OW7etxsC2zX+gIdCTdc
         Bofo+4A/DoGd9G2DCnitoJIkt/pU0TbERPsILSG+AjNNgRWFhaKAn7+0ex/2WiE5Gdoa
         Hp2ErxCU8JrxSiBU44kQnzw0ju9/RHyW7V8Xj5sF5nb+6T6vXNoG2GSKHIA4wJoHGEyM
         eidQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758720212; x=1759325012;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :ui-outboundreport:content-transfer-encoding:in-reply-to:from
         :content-language:subject:references:cc:to:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=qDWS8q9JVPJXo6r4BwVYtaF46QM2Tt32VTFfLXjXSeM=;
        b=Nh1EY6y11t9r3aTKtZKPX1U6jcTZCL5wjtvdR8dDNDbP8wOdPdQR3y9xTUFTTC2lVk
         ddHsgtbbx//jEaOSsiMD5g/0LX+yd42nM45aHIs1xX7vqOb4TP0TqdxwyAwSxRUeYA5G
         CCtma+LI+ged+miLZQ0LKzviaXpNl6t4NVbRuZQS5j6la6gpYR2/3+BjZih+GxKtVqZ9
         JE7ppHYEBAY7KxRw7urI9U581NXyOGRElfnso7BLsxpzGvtIEzGYKP299DNpf7O6OpVw
         9k/SfwTH2By2iMOaSBZaP8To22iik13GVMN16HKArY8lE/eXrnQSfU5Q6wZCwD0GNRic
         lU7Q==
X-Forwarded-Encrypted: i=2; AJvYcCVy+4EZDMLwPg/tGr3RqLnPTcpMUtJTIozIVvFyRLw5TFAQWPCri9D49ZPvwj4B1RoREYiZSA==@lfdr.de
X-Gm-Message-State: AOJu0YzppazHxycMgIh/zGR4iJyy+andNzt7PU9c/poVVFiXLSXrUeFE
	60hi3mM43SGHHMJb76G1P27sOcy1wQURUAGn4yRXv4je34JXUy0P5rn1
X-Google-Smtp-Source: AGHT+IGqWa5Wl8V7gNyWG5nqR/cWgo2AgrTn7yhWay90PAfhYSI5pEI6GptmRETn3qEBCwy9/AiQyg==
X-Received: by 2002:a2e:be20:0:b0:36b:5945:d3e8 with SMTP id 38308e7fff4ca-36d17dbbfdamr20026911fa.39.1758720212113;
        Wed, 24 Sep 2025 06:23:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd49H3AK7E4QuJA2/jGzFiZDLWw4d2iADmKZldqs6o0IBg==
Received: by 2002:a05:651c:40cf:b0:338:4aa:556a with SMTP id
 38308e7fff4ca-36b7fe82d12ls6883431fa.0.-pod-prod-01-eu; Wed, 24 Sep 2025
 06:23:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWaZGXwf9BqY7MiBat9HSEKc3BzTKmxP5mLT371qehtXdaFJXzTy6M8mDOJu5bDyO1rKvyVHpB2HmE=@googlegroups.com
X-Received: by 2002:a05:651c:2153:b0:36c:5c06:9aca with SMTP id 38308e7fff4ca-36d180d7470mr14035611fa.45.1758720208816;
        Wed, 24 Sep 2025 06:23:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758720208; cv=none;
        d=google.com; s=arc-20240605;
        b=kHfb7L0B/MvOrZVBuGvpctl/KIZef73VtxCAU8fq1SGFxZkD5CUBSwRZ+r11HwbPb0
         IUD7bA30kAFLPcZl0itJIHjeijuAbyS8yCmU8jsIRhR7h54May0mC4OSCEURSt7GaYQg
         AqpxAtfEHL5eigwNUj5TeCg0AKjxhyMWoWTW0t8zKdNVa/B1CRRV9aazDgIIPq/gosNQ
         3ZnRCwrZ73hUnK/u2nibZzGwhVzpR5Krf7Jj9VC4LEnYToWQAE/3A7eDZIEMXIZyK9Nf
         i1oMbLgd61X+TzDPXHNY9ae361T4HkAuqsrUcs8erctTbIihh5eDvYqGcTUlLH11LXD3
         wLFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=ui-outboundreport:content-transfer-encoding:in-reply-to:from
         :content-language:subject:references:cc:to:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=oUx7FQDk2SiuLavlx/HNjgWtSxwt+Njd+F6PUkWYXZc=;
        fh=rJrci2Mk7UYFZFEq5EX3Wk1Btuo+HnU1GbKUIpi4htk=;
        b=k1qvoDG9g7NsvxP0nR3iHUiq7To29ADG0O6q/z7cDNu1RZUninoJZTuZAJRbpp/7gM
         1YYsckRx/oXqi+sk5mbQ5vDU+ro1SiR+fS9EfqernwxKXF0UEpseUzMAanXEWIHpxsyu
         n1uIeldblcMo5kCuO63vQyYiHF5KUce8pUQVVs+gj6dCuyjns1GhxvIf8SKK3eR3zDcJ
         rwQAi6+VcnSeSmrp9hcmG31aFql+9WGDspcdcNz6dt7sGjfDw9WzDNr4p5JUAcyOeUqC
         tDVGntAqdlXzVhtgH4hUoI0n5ALUoeNkd49QAE5bljzlVDpzZzx2fzbK28WncXlcX+Wl
         KyKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@web.de header.s=s29768273 header.b="Q//IkjTE";
       spf=pass (google.com: domain of markus.elfring@web.de designates 212.227.17.12 as permitted sender) smtp.mailfrom=Markus.Elfring@web.de;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
Received: from mout.web.de (mout.web.de. [212.227.17.12])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-36e3838ec53si502211fa.6.2025.09.24.06.23.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 06:23:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of markus.elfring@web.de designates 212.227.17.12 as permitted sender) client-ip=212.227.17.12;
X-UI-Sender-Class: 814a7b36-bfc1-4dae-8640-3722d8ec6cd6
Received: from [192.168.178.29] ([94.31.69.191]) by smtp.web.de (mrweb105
 [213.165.67.124]) with ESMTPSA (Nemesis) id 1MdfCN-1uRnfK3hGD-00nFl0; Wed, 24
 Sep 2025 15:23:27 +0200
Message-ID: <8f0366c8-f05e-4687-817f-90a5b47922c9@web.de>
Date: Wed, 24 Sep 2025 15:23:26 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
To: Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
 kasan-dev@googlegroups.com
Cc: LKML <linux-kernel@vger.kernel.org>, Aleksandr Nogikh
 <nogikh@google.com>, Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Dmitry Vyukov <dvyukov@google.com>,
 Marco Elver <elver@google.com>, Mike Rapoport <rppt@kernel.org>,
 Vlastimil Babka <vbabka@suse.cz>
References: <20250924100301.1558645-1-glider@google.com>
Subject: Re: [PATCH v2] mm/memblock: Correct totalram_pages accounting with
 KMSAN
Content-Language: en-GB, de-DE
From: "'Markus Elfring' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250924100301.1558645-1-glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:GbK73zxLYoS2kQ137BowTVrHDqoJ8gk83c2ByReHUM2nq/LRqlh
 CZO842TFixdnpUk1ktMJFWudMgvfOEDHLgTrHpvgtEf6VDZAlIkg892QjA6IwmIm4AZAGQa
 oNuryIfeGvJ2wsDd3/FylPuN2EIt+UCxKigm6SB0DvsaAXNqmFhAss29qpFku4zedN1kKB/
 RSZKpA/cm2WPRO972GolA==
X-Spam-Flag: NO
UI-OutboundReport: notjunk:1;M01:P0:q/uBpl4JHmo=;6HT6GiaWj/LEuxTLU8Jcvzj9PSt
 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
X-Original-Sender: Markus.Elfring@web.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@web.de header.s=s29768273 header.b="Q//IkjTE";       spf=pass
 (google.com: domain of markus.elfring@web.de designates 212.227.17.12 as
 permitted sender) smtp.mailfrom=Markus.Elfring@web.de;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
X-Original-From: Markus Elfring <Markus.Elfring@web.de>
Reply-To: Markus Elfring <Markus.Elfring@web.de>
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

=E2=80=A6
> +++ b/mm/mm_init.c
> @@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *=
tablename,
=E2=80=A6
> +unsigned long __init memblock_free_pages(struct page *page, unsigned lon=
g pfn,
> +					 unsigned int order)
>  {
=E2=80=A6
>  	if (!kmsan_memblock_free_pages(page, order)) {
>  		/* KMSAN will take care of these pages. */
> -		return;
> +		return 0;
>  	}
=E2=80=A6

How do you think about to omit curly brackets for this if statement?
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Doc=
umentation/process/coding-style.rst?h=3Dv6.17-rc7#n197

Regards,
Markus

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
f0366c8-f05e-4687-817f-90a5b47922c9%40web.de.
