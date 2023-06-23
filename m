Return-Path: <kasan-dev+bncBDW2JDUY5AORBSFF22SAMGQEOXHKBYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 371D973B78F
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 14:40:42 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-5704991ea05sf8640577b3.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 05:40:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687524041; cv=pass;
        d=google.com; s=arc-20160816;
        b=vl+4E3rQTCQVN1/QAVGytLZP9WPRgjJp8MsEoSl2GJLJIcjIiE2GXH0zMo5aCrCaTC
         GTXKG0x5EzTUHz95DBxoWquVviEi/uMlFyBLt1yZvpaO7DrXDlDcW7x+t7I1fVh0GEWZ
         uwjDNc01CDsUNOn15/3lVEihngb1SrnFarIJpaIkccFualiCI+1B2deanDzqjW2TIiNl
         NTAtNDCtlMLPqwZ+5vpUkFU8HrHx4EGTqyuFc7ooqKPFDRRcXccm6XbMqtc/n1kGTad2
         AtB6uXoc1X3YesI4TZh8Li73PVWCSuhxlAScnfh8KAgMs48dp/yqmEZLciqf0Bu1IYe2
         ZcUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=v+3vvLM1+Mc9jh4x6MXIFIrxTjP1jPXbGVFINOAwTIQ=;
        b=hrGA3T0a8uXuD1QQeZzdIr69Piths86wqg8HOQpTZfWTzTVYOo/0GBHsmb3WMxDzDs
         xU5QNfcRRFOVyApZFW91NvrmRnpjyDcUqt/Xo+Rdv6RYHr1e1Oy0wW2b6b2tgfJ8kD0r
         fJx/xrTCk+DL/Z27TTTiS0EsnvlfssFDUdaa/nxa+BWE8jxxi4f6FetBlycKB9fa5iUv
         UPbRvcT4Dw7B/BKrgFWvdfUx/enbwtDBpWNA7kl5T/hUrI64LRGMYmXKJZYJ5UqZ+0Gj
         KScZD42rasWc1/0/q7Sqcdc29rWPH+dG91DDHjJpDlGnn0sG5d1o8cKO3LbAsA5Uhy5r
         iHtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=ZaQ6V3LF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687524041; x=1690116041;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v+3vvLM1+Mc9jh4x6MXIFIrxTjP1jPXbGVFINOAwTIQ=;
        b=Tzr7sUMuVxEZusJdS4/QtkaGOBvvzkqP2hKB4e8xNNE6hFQTrad0AJz5IXa9omoyHP
         KHSZ5CVIprrccvFnC7iAklpN5u1gugEJasVXIWHP4UPDzs1H5UwOqpef0i8qA2HmKXOf
         IfU0LKgHonbM3A5dYtCx4NWPeMeJ1+xZNbm2iBM1M6CotkEQMckIIQFDYjENlRzsTRX/
         1ku9PTpCYRQCBVqsYpJPEcLyTy1gqXJnI39yeNnU0iK3NNOuQmwNgcFjI2ica29BIkFV
         j/GcPIKLUwYqdQeu6KziEZ3fo6c+u8A/xjlZgXpR6Ycj+hAltTUq31urdCWrwFignT65
         OS2w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1687524041; x=1690116041;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v+3vvLM1+Mc9jh4x6MXIFIrxTjP1jPXbGVFINOAwTIQ=;
        b=RIZka+K05T4PQU6h6jxDfaOuyYuZm49+G36qC25G2vSWhQUqjV1RuM7/5zJLMC1iPD
         jW8w2LTMUtAs/3QQ5EljikaEQ4njlLwK0A/HJeKqC+atxf1OA3E1sXli2rBOntszgDnJ
         mg1cH4GtxT+DGJo1Rubh7wg1kRutZGx09U77wCpxcwAwdzQhiHEhVnewMHkGhVWYeEPt
         FaZLnpxZaK2IzslSUiMzQau+xbxcyyy405xhVx22IrJm2fAzJ9POYNU3pUvmw1XbXIA1
         hohMAcmv20n8JALuH9MD6G5yns+rT7XZs41TJbXlLGdu1R7nqUNsaHaPxSpbhca88wbt
         UKkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687524041; x=1690116041;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=v+3vvLM1+Mc9jh4x6MXIFIrxTjP1jPXbGVFINOAwTIQ=;
        b=egodA7GxMnJ7ir3Jj19b527mSENoeB3sfLh5dCa0GvWzz70HQ81uiIIJcBifME+HSX
         CgfsFbaCCRd8UYFFnJn778YM4oKeH9yqbseUGqP882+vshbNhg4oI4C1WzWgNGCZBaMA
         8FM3N70EEqDb7w20GbmyBR6X3uobuqdThONhFqwM4G2Rxs8EVZE3Ug/PaG6qOJ+tnMDZ
         rVHD4rQNY/XyDdBpnboTgaDSo7CThSLl7O/7XB5NxwbDhS2IvXgX8sk6V18KTfIKRRtd
         UrXM+iMdZtywkFrFI8uUog76Emgy+8vfygMGTjO4AbZ9hLJi+RtmJytoPh9PQXC5GXJd
         dIZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyM8DkRhebwzhymbw4inhrmt4UBX6r+CP2ztjyOKcDDtfwzDuY0
	Q/uhzoiF9zhCZ3ui4V4wyrE=
X-Google-Smtp-Source: ACHHUZ7l263MhO39ZHMoj7X9AJQpDYfWDaR/HhK5sISZgN32UTs43fgeA7hcSmXDz5yqXBNhMsHkjA==
X-Received: by 2002:a25:6b50:0:b0:b9e:6fd1:4350 with SMTP id o16-20020a256b50000000b00b9e6fd14350mr20771243ybm.17.1687524040761;
        Fri, 23 Jun 2023 05:40:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:80e:0:b0:bfc:560e:9eed with SMTP id x14-20020a5b080e000000b00bfc560e9eedls269059ybp.2.-pod-prod-01-us;
 Fri, 23 Jun 2023 05:40:40 -0700 (PDT)
X-Received: by 2002:a81:91c1:0:b0:55a:6430:e8fb with SMTP id i184-20020a8191c1000000b0055a6430e8fbmr25923635ywg.8.1687524039951;
        Fri, 23 Jun 2023 05:40:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687524039; cv=none;
        d=google.com; s=arc-20160816;
        b=XR4oFFipwqHNo8Qqhbs0Ix6p5aIx6jCokSOl+jk3pgOFRn/DC/DrM9wYnbkOXYaKFY
         xQ4dzVYER+5XoGtrfLPvcARA8fCMsoCryjx177HX3SUsJtQPa/+d3+a7M7eaF/nzBmAh
         oc41M3rzAt1/8rzqbslOXyLsgXGqkm7S3646uOjq5gMeHzyU27zhCmFNiijUHHzO6Uj8
         CZwQWxWdUpvDbX+141GaS2OLJfYYwPmZU2LdN6w+ScvJNQcrhOJr9ANBIOY7XsxV2irr
         GWna6E2zypaUul8Kv6ZQR0Yl51EoWSMD/U+pUZgh/azvttn5ILD7cOdvIi+yuw0MUVPi
         bGNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ISCGsibdUDqUNcisOUEtsn5XzzcugHFWIWC+2smDI/w=;
        b=nsb1JMqELEfLWkv842R7UtgdibqlEL9h8/LvbPIU0Xg0S37L/jqvACX/04KjT4b/M0
         7L6Q2hElM84aSQ0R1ZY/PX5YGEv1opkZDc7bcH+vNvCquq16d3r3KaL/t+N1lPHM6VTp
         O4e6cNX+O540E308DfOG6FYT/zboTE7hxgsDrm1jA7iKn0eoGE1qrGNGbEeazvpLu1rW
         2mK0ICvZAXWAw2K5Pygjba/88XG5r0/GNl1oTigJuWQzxx48+yU4fMlK2fpBNxO0/OCs
         NYSluHomh0R28em+ztqPsRAgPf5bDcayRSmrTBY8z189DKzvXiyg4Sxhg3IctVzCU1kG
         65tA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=ZaQ6V3LF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id bg19-20020a05690c031300b00565aabff14bsi793907ywb.0.2023.06.23.05.40.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Jun 2023 05:40:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-6686a05bc66so297307b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 23 Jun 2023 05:40:39 -0700 (PDT)
X-Received: by 2002:a05:6a20:4410:b0:121:7454:be2a with SMTP id
 ce16-20020a056a20441000b001217454be2amr15686808pzb.45.1687524039092; Fri, 23
 Jun 2023 05:40:39 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZfi_o6QbfDamUjsPXjtnEwKyBn8y+T8=zxV2mEpA=DUyQ@mail.gmail.com>
 <20230623075805.1630-1-chanho.min@lge.com>
In-Reply-To: <20230623075805.1630-1-chanho.min@lge.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 23 Jun 2023 14:40:28 +0200
Message-ID: <CA+fCnZfrUY+EZ8w6zDhfjOr=JSFS6bHO7JjVHx0pEykNXZQecg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix mention for KASAN_HW_TAGS
To: Chanho Min <chanho.min@lge.com>
Cc: dvyukov@google.com, elver@google.com, glider@google.com, gunho.lee@lge.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=ZaQ6V3LF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::432
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Jun 23, 2023 at 9:58=E2=80=AFAM Chanho Min <chanho.min@lge.com> wro=
te:
>
> This patch fixes description of the KASAN_HW_TAGS's memory consumption.
> KASAN_HW_TAGS are dependent on the HW implementation and are not reserved
> from system memory like shadow memory.
>
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Chanho Min <chanho.min@lge.com>
> ---
>  lib/Kconfig.kasan | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index fdca89c05745..f8f9e12510b7 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -124,7 +124,8 @@ config KASAN_HW_TAGS
>           Supported only on arm64 CPUs starting from ARMv8.5 and relies o=
n
>           Memory Tagging Extension and Top Byte Ignore.
>
> -         Consumes about 1/32nd of available memory.
> +         Does not consume memory by itself but relies on the 1/32nd of
> +         available memory being reserved by the firmware when MTE is ena=
bled.
>
>           May potentially introduce problems related to pointer casting a=
nd
>           comparison, as it embeds a tag into the top byte of each pointe=
r.
> --
> 2.17.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfrUY%2BEZ8w6zDhfjOr%3DJSFS6bHO7JjVHx0pEykNXZQecg%40mail.=
gmail.com.
