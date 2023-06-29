Return-Path: <kasan-dev+bncBC27HSOJ44LBB4NL62SAMGQE46C5GDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F1E474286A
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 16:32:19 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-51bdae07082sf6255a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 07:32:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688049139; cv=pass;
        d=google.com; s=arc-20160816;
        b=E1ODrMAKhTzDEoerDj2ux5UkhfL2cTTlnio/rVvO8b3+Pat0In1ZUgZT49DNU9VnIr
         kRNPcSD1AqFesLSIB0RZjXeRYrWIWapVQJ8JL65EI+hvvjC2N2G89CgOU928zDPR2JKI
         G5iXU0quVoCXscO/3yT0m4+vxh44rXWMYA4czjdlOtU2ftvuKjHwmyT2pxNO/4flMy0u
         1YRdfYYnqsa/wkmQ2wNeqRHg1aHc31v/55pqfG1NygiXKHllY2+wAvm4Nm9ohDoJAgdF
         tSiGwNdTRpScgg79KlaNugKMCtOxKn70PeMcAX+A6gFWgRYoWzWQzE3UwEsnVNSJ/Oq8
         7Q9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=Bdl4GukW+95JjyQTB2+mySgJ9m835M6CJ84pTiVQLAU=;
        fh=ahv+sLqSQp4RXPpG3gPc8Lw+Y4xXVpwbNW7oD3JEtn4=;
        b=YN6grP2Xou4NsiTH9sZYmdpEMNE4bcgNAdWjzIfC7+Xc5lqxnh9YAusqTUxUhmQz2C
         PB4tiH4kWHQxypXuTkYGvP0RLD2jupzoP1K9Q8+P/AmjFFtaPIA94GdH6zRUk7WJbkhj
         zAn02FjikrMeBcL8zlMKgLv3CPis8/moHtakAwSZVaEwSEprQgJo6dDGCQOoArsfvqLA
         YFqz1UTroSmngs3T7+wB0AHZ1HVNkOIwc6V4sEJolKgEIGVQIPNXgcQpxI2n008EhYn3
         SUQ1Wa8eOgAdX6wMPtI2PU9YXcXCHiCx5To/Vc4rlsn7VnBGi2a4b1rnI+iPZM9FQXMq
         L/3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688049139; x=1690641139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bdl4GukW+95JjyQTB2+mySgJ9m835M6CJ84pTiVQLAU=;
        b=Ce8A6+36ousoWZvp/A+GvmtInIDa3xY4AutDLgCm5lMGrspkZWH0wQmDrOY1uev4lJ
         n6Sis6NGOt8WQ6iI5Kz1jC3zGMImExXztw+lCqlDl46OWsKznZrxnPNm4btVh6SYNVg0
         tURkwUmDQn0o85ka+mkA4wI43iOm9RvJfpY0/pwzegSSglPQUFXclJAu+/CwDbQg3Ri6
         WU9X9yhWs+Mw8uWTzV3tcqXbWOfGMGFmXl9rUEOLoatGToSSAj5FO5tKvaIs21/uvRJh
         6sWNE10bEoM6uk3jCtFLdUIavE1QuvYQWmqOVmPvuHjLLo+S9p4b/ovIXKkL6AATk6Pp
         mREg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688049139; x=1690641139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Bdl4GukW+95JjyQTB2+mySgJ9m835M6CJ84pTiVQLAU=;
        b=NSPPqyum6mZaCXvqDOD+DUAzG2JagZj0NFeElJfehtqRnWvti3L89oEEZRZPjRG++r
         PB7eng960MdW5ZRudb8bjSN9NFxyEw4Y6a2P8KkupOPA9l9IsnlE7/g5cl4KnY2+mKeL
         71s0lBRLGBVjunYHlzNt97D7xhThBO9oMTplttSJkJAW0Myc15KwQF1kMh9Ok5MSnfSt
         GHm/szJWApfp0zcjc74WABT4eXUCYUiHn1SIrl6t+al+vRsAN24bvsrsEqj6jiYj8KeF
         gii03iU0HPtpuVIZr2IpVU9i1rsPJ53hVJt+RX9iRLXulanzJ3xOynPEW7hvMy0XX1Vk
         HLMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzPOKdyGadQPr8W/yGGPg89cxlBytK2E1Iug0jZ4yM9LC05+3Zk
	nZfLVigbpLSqtYN7jntCzW4=
X-Google-Smtp-Source: ACHHUZ7QhDD3U2B1NNjUpK96BOr2fvrrlxyciWMnkQ5DfFocCWq40ZvFxyX1TCMrrfCWmghxuMWFcQ==
X-Received: by 2002:a50:c01a:0:b0:51a:1fd1:952f with SMTP id r26-20020a50c01a000000b0051a1fd1952fmr130664edb.1.1688049138109;
        Thu, 29 Jun 2023 07:32:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d898:0:b0:51d:7d17:4016 with SMTP id u24-20020aa7d898000000b0051d7d174016ls384883edq.1.-pod-prod-05-eu;
 Thu, 29 Jun 2023 07:32:16 -0700 (PDT)
X-Received: by 2002:aa7:cb09:0:b0:514:9e0f:889c with SMTP id s9-20020aa7cb09000000b005149e0f889cmr25478211edt.16.1688049136731;
        Thu, 29 Jun 2023 07:32:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688049136; cv=none;
        d=google.com; s=arc-20160816;
        b=Rm66lrFXXdIZJg46WI5ek+P4y+4G2pQMf5Y8q6vFoKtbSccHvGIeRiojN1hq+2XhIU
         q62ORq25gp/5X41cMZve8xsPiD654rc1gz5zqmOf0JbU6t/8q7nMonPbxSpFaPBu12oQ
         X8F8joHsiDVuTJAiPuAr1mQUsQNk11EtO58idhotT6nn88bWFpjuWtdmMre/DVqzQaCS
         zArnSO2pCO3/4gJFaY9R5qVVZlPpBOUYnnx0EDsWwpNAfjPsNGHa68TV1p6oKvpowl2R
         4vy8VNZhHoagwOG2yJSZo7ErddlH90qFKRDEp3jo3/962D+7950WbXhVgCqqERYU8kD3
         NI4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=ch3ScGyh52zc65er2zOJWk+Dm2ZHPkLTHUaOcDWKL14=;
        fh=deMgYpZcS1uGAnQCuPoOhLRoqRlez7S1d+5ISp7HW/8=;
        b=V5EAyAp30rd38a2Qt/G/nzPldeNr0b+Xn/liTZVQpaly3pBIyQKGjumoI2X4B8w/Fd
         J4GEJlZGa3Xzuwklm6AhKab5V+W8FbEvjZeXBDgBiZBIkzx6KGSOH3k1iK7e38tc/+Qi
         f2tOZPQxWeBBbB6EWFWrCv0nIXowRQTxMUyKaON69s5tW/glGPRBah+cQvagVZGJDVZ8
         yC7lBJRaHSaUN/KatoD/qHemMwUtkpapXDE09TxFy5oV+vTg+vcfohMW0q1Hf3VXmR7R
         pd2uSq2i071pA0tvjx8jUjICWQPptKtBm+QCSRWZ4XjMU4+8X6nGtaL/mCfNSSmQ6ZQC
         Zhbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id bx17-20020a0564020b5100b0051d89315ca1si846556edb.2.2023.06.29.07.32.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jun 2023 07:32:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with both STARTTLS and AUTH (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-109-zbBpsLNbOwCDzi8T2c0qSg-1; Thu, 29 Jun 2023 15:32:14 +0100
X-MC-Unique: zbBpsLNbOwCDzi8T2c0qSg-1
Received: from AcuMS.Aculab.com (10.202.163.6) by AcuMS.aculab.com
 (10.202.163.6) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Thu, 29 Jun
 2023 15:32:13 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.048; Thu, 29 Jun 2023 15:32:13 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Andy Shevchenko' <andriy.shevchenko@linux.intel.com>, Andrew Morton
	<akpm@linux-foundation.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: RE: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
Thread-Topic: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
Thread-Index: AQHZqdYu4WwBl+H04Ei+qjwMbhdjFK+h2Qxw
Date: Thu, 29 Jun 2023 14:32:13 +0000
Message-ID: <6b241f45a61f40fe9b221696289fd658@AcuMS.aculab.com>
References: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
In-Reply-To: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Andy Shevchenko
> Sent: 28 June 2023 16:34
> 
> We don't need to traverse over the entire string and replace
> occurrences of a character with '\0'. The first match will
> suffice. Hence, replace strreplace() with strchrnul().
> 
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> ---
>  mm/kasan/report_generic.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 51a1e8a8877f..63a34eac4a8c 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -264,6 +264,7 @@ static void print_decoded_frame_descr(const char *frame_descr)
>  	while (num_objects--) {
>  		unsigned long offset;
>  		unsigned long size;
> +		char *p;
> 
>  		/* access offset */
>  		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> @@ -282,7 +283,7 @@ static void print_decoded_frame_descr(const char *frame_descr)
>  			return;
> 
>  		/* Strip line number; without filename it's not very helpful. */
> -		strreplace(token, ':', '\0');
> +		p[strchrnul(token, ':') - token] = '\0';

Isn't 'p' undefined here?

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6b241f45a61f40fe9b221696289fd658%40AcuMS.aculab.com.
