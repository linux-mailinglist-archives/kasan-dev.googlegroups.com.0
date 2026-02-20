Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDHK4HGAMGQE6VA7WNI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IHX1Hw91mGnhIwMAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBDHK4HGAMGQE6VA7WNI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 15:51:59 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 21096168890
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 15:51:58 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-8cb403842b6sf1802911985a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 06:51:58 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1771599117; cv=pass;
        d=google.com; s=arc-20240605;
        b=OdhxqirMaPdBrBK2lPRERJWlwlBSJjE3NVfGqOjGJ1pDSMiL9ya21iD79q7SY66eEL
         mun/kifqGoyAYDkJe6dGwILp1LOB8HwL9F1Vty48S/YeVEu/W6sjkT3XORWzdoBnETY/
         JLXr4sjCcMEv0Zub7KmDlu2EbibwfvcNBSEbvW12UKT9T7g0y/18uyjtfiUwGQzL78E3
         fRzWbwYWSWrV8zUgI83U6npA21yVY4PvAiMXrngnZMPkqXS+vj2BfBSeRaLUd920adXA
         /OITcjQlTL20oTDwRzw93wXOSowqiKSibo3LvER0JuT0x91GPwTE0z1Q3wBX+WD/t7GF
         pgIA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/1XCALwijg5PRB39Fq21Dp1E01tJxaZf2opQd8SEz6k=;
        fh=LHLqU4N7VzC87zxqx67lWjHYGMBk+gi2Af1waY5uTdw=;
        b=FTJcvowHTqqVmZFU9oHEmDTTqsxwUygo5e68ra+ys7RbRqsFm+juZNAx4tig2FV02Z
         kIU6+fof1FisWN5ngOSSiaAV94zmJjjec0+EutU7NKMyzOPnsU/j+M8rTgfk4NiGJTd7
         K+nZ27u+8zG7XKksTiMHn6qax1KN9PEQG+KmdlHxnc/OVEyy6mPejM6eXgJQ/nERxZqW
         Dqnd+tKulwuD/DP1gM1aUqazXAwKeFGNOCTOYmzRLMdeAoE6oxD92KsplWZjQyOfk/gX
         KAL3xpUSEWw9yPwz5jMniNnoBYZ4vNC0LIX3RiC1Ukv6zsyRiaWIMm7b4fi0l4Z/nfUm
         lRbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="ogfy/Mn3";
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771599117; x=1772203917; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/1XCALwijg5PRB39Fq21Dp1E01tJxaZf2opQd8SEz6k=;
        b=Ln3sj/Xbhq3viAxXtBq5dczd6fcrhIk6zC9gPh4XNKKN+AnEuOyz8/4paLKo0i8kn+
         ZXqWEQwLnFE0fRfpHNwvuObN1iowoACi7I4NCF8rxfa3YOsbZXxoRbt4sHayghqmXULm
         E2YcrtUYGepiVtscBYxiYTJdfYjUTupuk0imjCmPLNHrjtyJYOn70gL2gYaKZe+Fqkpm
         1tTy8ug/96BoPXoOF0F/o2Lg28DqjiJhF8xv5NgB1181gvRGuhgkUTSfFN32v4uMR5NS
         U8rAtDMUXC10BaIVZf0M9Sj7O0bPbWtuk+4P7OnSfbv0NhozacD3E29n5V7NppcIDAgu
         0HTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771599117; x=1772203917;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/1XCALwijg5PRB39Fq21Dp1E01tJxaZf2opQd8SEz6k=;
        b=RMz9PMJFkOK0LU5WkE1StGEuntUA7qXtX2VLupO384TjtwDK9VTAHWX8K/O/Mj83gz
         +vhmOC9sJrfEIXwts+75hsYCadbXsU2AE2uGY7XvKp6YRfg9OvDGkqCJgYfNIDexe929
         fRpTcWu4h3Fa32iCEK8DuXCTaROxXpx5It3xyhTAnwuz6Z9B5L1WI8Hm2uSB9ERMxSPm
         yFmByB+h0x48NsYDwghwBoCAYLfBxnO36dLyA/3jw6dsl2HH2mFb2ZToKYGmmZIsM8Ub
         G4gGeR9LbhSUlPd9R6fshdNVLmAVYdXDMWtS5gzXxmTWaWKso78DdlSuEHZVH2hfJiD0
         p9Eg==
X-Forwarded-Encrypted: i=3; AJvYcCVWae7B/J7ho0SSdJQh7zaQsICvgvFIZ+onKrBfDz/otzilqNyDO2cnJExEcOE7Ei5f7wpOhQ==@lfdr.de
X-Gm-Message-State: AOJu0YyPm0SAcBRVboYXpYurPjtkaJ4TC3p8XI0OozVQqLLm7+X96YOW
	eS6wBgPXJE5ouNis0902aaz19FrLONclmI2rUdgVCtfTkJNYK9ub8gur
X-Received: by 2002:a05:620a:191e:b0:8be:6733:92ab with SMTP id af79cd13be357-8cb73f2d70dmr1049801985a.0.1771599117248;
        Fri, 20 Feb 2026 06:51:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HlVObqoZ00kjGp2TCtlvO8+IEkCo7qfp8uuBY9eRIJSA=="
Received: by 2002:a05:6214:484:b0:896:f564:f3af with SMTP id
 6a1803df08f44-89729e17493ls56298586d6.2.-pod-prod-07-us; Fri, 20 Feb 2026
 06:51:56 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUI/UuezKHebXlqsPFRQWzyy0F6X3uAK+AU7CwYXUVE2ofVq2jw5qwE6DbrsMyXxgjjc6BQzJchHOc=@googlegroups.com
X-Received: by 2002:a05:6102:d86:b0:5f5:773e:a555 with SMTP id ada2fe7eead31-5feb307aab2mr16364137.20.1771599116126;
        Fri, 20 Feb 2026 06:51:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771599116; cv=pass;
        d=google.com; s=arc-20240605;
        b=jQDdASiNRF3Y/6zH4r7puAGi5ScvGPPbCuCx59GhgXX/SZ3Svp8pVJVrYKemw+JeyV
         bd8raC5ks8F7k9e2LWILnpvKmYbvsktX99QIgDnwRWi1G5FLMd8ZWxfaIxg7HLNME11A
         L0SnBwqB6KM++0GlRVDIGrq6q+EQdFfTrZP4tqqew99xUI4p60uoOZqz2/12QNZRejJs
         ut+MJJ8CwmBKzzmhnaVmmm0LCZ485QclCGcGpoOEime74n18//ZoUN+Qi3tP7RTlQL98
         c9LMhgN6AsV6azZqZU9Xsk9VoiI1ImhHBFKzBoqWWDhlsYlOAPycjhWTMZhFZHOWF6f2
         xFVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CRC9wX3iNFw/rKwvWg64N9r6jXdqwQPIuFwNZXF8S+k=;
        fh=AwTt8RdXebp6jAaolFkobM7onBloRQYokijJyAs6Xmo=;
        b=DqEacLL01luvQ3BHYDdZCWhE+pZYyKWhvit7301kP0QGNUAgeDLZsauzr0MteNYl5K
         i+fU9vltL/uhnUT27HUtw8vip5R4aMW2QqZl8BlHD9PqdGgsJEn7x+0zOpJL8vU1fJ9K
         q1DaD/umcDcZcy1iOB2/Ag6+wOJReCUKaYrjjcT6WzWaPP0cMTZxk/66zWhiC0I8SdzB
         iIf3LpiIW4Vs1WHkw0Bd6EqPn0yArYOZiP8KKm9M4cyOeTyoBjTPgLupfVH1+Tj6Iz24
         fKYzrkm/Kv/2Vw30wGv1Ug1Md3o/STfSkfvidORIlaQIRMVVfJzmCQX0z+UtDgwy5icf
         D+3g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="ogfy/Mn3";
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-94afd26388csi1031171241.4.2026.02.20.06.51.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Feb 2026 06:51:56 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id af79cd13be357-8c6f21c2d81so203635385a.2
        for <kasan-dev@googlegroups.com>; Fri, 20 Feb 2026 06:51:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771599115; cv=none;
        d=google.com; s=arc-20240605;
        b=gTiOqXzN19088SH8QuZi/YIwkIfmd4iARgv7yTamJPTApEAe5KUUiRfCkPt7hKQbdQ
         4YQ/yGaYDXQVxuHVz9DqlPf8+nKOrW0lq17mpaD/s/huVP6NME7YnWRht2vS/znoE90K
         h9DIAisAtbhuNTz6MUlOHLI/Em8E/DOFtuocC3Yk+KZ4lqiDTCXpnM22CJStse0q6Rd6
         98qPhdKBqp66e0HNgsuVl++ppg+lVLU0KKreKtbLKWF2Rb4vwFZZTl4xuP+2ZT5+AFrO
         5hgsmrxwgW3v5SWK+ZWsrTAyQ0YjbnylDeuk+zlL2xB1+5G30qZlgW3pY9JMHz+bv6BC
         Sasg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CRC9wX3iNFw/rKwvWg64N9r6jXdqwQPIuFwNZXF8S+k=;
        fh=AwTt8RdXebp6jAaolFkobM7onBloRQYokijJyAs6Xmo=;
        b=i948pG8Ki2ci84jTRAh0BjFSdISaymCzWrz7UoAalaPQ6vBicmHbbxEOptc1V2Vy5B
         F3wb3EB96YqNaz4fKZaOZ2946mTa95kvrP6AXlRFIHJUtd/J0BOEzTcsuuWqfcDI5+pP
         sp4CsQk4y46QrYJjCiCak6XMHsSHnHzPXSlece8n+T1pFHWk/peJlLIyNs/Ug5xkinZG
         YP0r1C+BIUdftjFsIXR3Qzfq3bUzUU0dRGbQ1D+xkUOHStPphjoMMKuryvy1bCZ2TErW
         7q1LCz0jfVE4kuVXfnCeSPvCjRjeIKQCFrIcel3iKOhac1IcJVqpQSAbg2Bv5mTyluY3
         +5Xw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXGGK+WbvSumF0z/H0lyHCka5aMauK19huBxLYYmFIk6Sl8EZ9rDfbNpl5CVuA9AZulUMPKTY/2m8w=@googlegroups.com
X-Gm-Gg: AZuq6aIYx7gMVbHAbmZuHfH6Tz+1yZYvFT4xIkcWOQFOpeNnaKWLjmQM5DUydpV4vx7
	Olnrn78RCq3qQg62LPs1u7octiIN+18J7x9oGUNPMGHwW0qjun8KV9IbSqdxX9j/q/fAPGFmSi5
	jknCmxdJPPe5iVSSMA9pvvvriEZiZa/jSqzmL3C8hS+CiiM2fRBzTIgAOnJN4T8iVmGmfK7LYUS
	9OvyQg9O16kg1xQUcPCFBEu96Mti1V/mxTQj5ldIoT9jZIDm110F7hRmTAyqGZYXJu6667e4aQ3
	beZYB5TRG/Q9YoYqeE5AulQfknXbmk888tGyJy7kPXgZ7IQd
X-Received: by 2002:a05:620a:2995:b0:8c6:ab8b:29e3 with SMTP id
 af79cd13be357-8cb740a50afmr1032496685a.44.1771599115069; Fri, 20 Feb 2026
 06:51:55 -0800 (PST)
MIME-Version: 1.0
References: <20260213095410.1862978-1-glider@google.com> <CANpmjNPJV-aQKnQ7Mtr6e8_12UR3C2S3abJx_ePFWmS1WV_UVg@mail.gmail.com>
 <DGJT8E07A37R.2GC7KEDWEI7R@tugraz.at>
In-Reply-To: <DGJT8E07A37R.2GC7KEDWEI7R@tugraz.at>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Feb 2026 15:51:17 +0100
X-Gm-Features: AaiRm521oqZ4C18Oc-qFEQM1txdUhdvqiUI1K2F1OhtYJjScl8iiQRwoFqDDN0A
Message-ID: <CAG_fn=X=Jvm1bPo=B1f4oo9eSAsHN0QBcu34oi7cMC+Q6--ZAA@mail.gmail.com>
Subject: Re: [PATCH v1] mm/kfence: disable KFENCE upon KASAN HW tags enablement
To: Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>
Cc: Marco Elver <elver@google.com>, akpm@linux-foundation.org, mark.rutland@arm.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	pimyn@google.com, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Greg KH <gregkh@linuxfoundation.org>, Kees Cook <kees@kernel.org>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="ogfy/Mn3";       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBDHK4HGAMGQE6VA7WNI];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_CC(0.00)[google.com,linux-foundation.org,arm.com,kvack.org,vger.kernel.org,googlegroups.com,gmail.com,linuxfoundation.org,kernel.org];
	RCPT_COUNT_TWELVE(0.00)[14];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[glider@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 21096168890
X-Rspamd-Action: no action

> But this requires adding __GFP_SKIP_KASAN as allowed in
> __alloc_contig_verify_gfp_mask I think. Unsure if there is a cleaner way
> of doing it, or if changing __alloc_contig_verify_gfp_mask could break
> something else unexpectedly.
>
> I would be happy to try to submit a patch for it :)
Sorry, I was working on a patch when I saw this email.

Let me send it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DX%3DJvm1bPo%3DB1f4oo9eSAsHN0QBcu34oi7cMC%2BQ6--ZAA%40mail.gmail.com.
