Return-Path: <kasan-dev+bncBAABBYEASGKAMGQELOUUDLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id BABB152AF44
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 02:40:00 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id i131-20020a1c3b89000000b00393fbb0718bsf2089675wma.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 17:40:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652834400; cv=pass;
        d=google.com; s=arc-20160816;
        b=yu5jbqGOoVqvzrch4yO20pdDr/dttdm8Itr5r2Dx+QzOu1CiyaN7zIdCBe0130KPJS
         7c64X4cjb4hLCE6m1gmwEEcLi+UFudXJQV46N0aMeCApd1G3WwShovmL9+2UDKqWE0O+
         yEuTwCOIzKKN1dgu1z6YSMVS5b6Hu540aoDnLRGkxxvBQoHDi7F2v0Uh3Rh0v/kjAXIk
         M2YditjW0FC4quY00jNWeOoV3VJVfu5HckWVinVK1L1Bp+9XJ/6HCikUf5igrzBueQmK
         5+Tazyw4eSSXSUdgbTdtKPKZBLoRMrPJpCO229aZ1Nqjzon6r39EhG9eYq6LeoGrAHvB
         GPWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:cc:to
         :subject:message-id:from:content-transfer-encoding:date:mime-version
         :sender:dkim-signature;
        bh=VI/1fMy3g3AR0cnXqw+CFVw7M/voWaNPWnizywztC9w=;
        b=ZaIPIwvE12w42pC45HQ98d9eYAnmV9nRUV3XxUJlGNyeflRONnZDHqoUJp7bc7kows
         srZnGep9mlAhE6WKdVReo92uHsDolMU0wBvC7Izl+BFNDdkqP3eSIDIsMJdTZ4uhn2fM
         vTcZYx6MjjkwnnzciX3epTLhVz9ySrstFQlkKiGAIRmDjQ5zCksUQtWgJJRNHEgp+6TB
         VkyNX1JLD/j2GbXm7IO2P51xKfebK/feahzB2zwYKtvriK1VcfAYqjR4PRvtQwuWOfPV
         soqRLqet5rfC5Ukq98Jda7eKcY0Oj62U3AybZ2DzamS42J5+EL9NI08MezXm4oN3tf3F
         HeVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kv2pu9RW;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:date:content-transfer-encoding:from:message-id
         :subject:to:cc:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VI/1fMy3g3AR0cnXqw+CFVw7M/voWaNPWnizywztC9w=;
        b=Ca/kLAZ44yFetsRfQZnI5/+us8mZpH0/yatTZagsXUfRAmGfccYizpHTavGJ6y96x+
         fpwkQSMoNn4sJUs66ofYragGBnV10cCP/wOasgOOr4zblJl/wvWAamz8AD3ijB8cEATs
         gX4U8DD3fVKpJ7xRLHKXWD+x1g7XeHxgnUa6bgMdZsgHEq8LFcSgt+YCdz+KKh+YMwww
         uYU6TMI32ltQ+Q/yWUXprXiGYBN/dhyUghwmqi1rpb+B165r7UOYWcaWzTqkraHYbr7M
         NGJobu+gC8bijbiU64E8ViH5j7byxndtwjW3gM5KeTGfSov9FZag6h+/pXMQWtfQrLjX
         63LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:date
         :content-transfer-encoding:from:message-id:subject:to:cc:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VI/1fMy3g3AR0cnXqw+CFVw7M/voWaNPWnizywztC9w=;
        b=YHMh1qiIEQqeCbU8tzSVo+letSCHBZwa4gFbLR+zpXlyu2qZB1mD96wH0TZoBH3nf3
         sPpiXuGIGmKobN4OLfc1ePRFLK113tFZwXJ9H5cDUAmvRqdJv4sr81EjT2hJSq9SE3x3
         vJiYl95KbOc9x7kIXcLNuK1/Mkt2MuvN8dnZiB+WrOq3e3ehDWYqkJuGTa6kIV9vJYZL
         ar09uA7sM0mmyIKVlO3Th32wnrA9YgDPtKjjenwLWcjsDJAIDqChB6fTJSvjlUMqkC8L
         5y/6iVBZIrLwe5zNP4+xaG2W+mT4QJqXTo8oaHwmC2uR4KRBWKKvjhg3O/7ZS81YpGsj
         Pn8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317lliA1QxPaIeDssBmS2KpBvJizCHxt3xu6XjgPj5NfkjaNN0v
	DIREeR09aAqViUUYFryHXWQ=
X-Google-Smtp-Source: ABdhPJyFrEq2kBid0K5B+EYVHlIbOkQwp3YtI/iihmr6MKR0c1HtbZqB06lY4I0kVH4QKUln0fQ7+A==
X-Received: by 2002:a5d:554a:0:b0:20d:544:a3c9 with SMTP id g10-20020a5d554a000000b0020d0544a3c9mr12178520wrw.699.1652834400379;
        Tue, 17 May 2022 17:40:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1567:b0:20c:5e04:8d9e with SMTP id
 7-20020a056000156700b0020c5e048d9els5099963wrz.1.gmail; Tue, 17 May 2022
 17:39:59 -0700 (PDT)
X-Received: by 2002:a05:6000:144d:b0:20c:7829:2a44 with SMTP id v13-20020a056000144d00b0020c78292a44mr20605020wrx.663.1652834399594;
        Tue, 17 May 2022 17:39:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652834399; cv=none;
        d=google.com; s=arc-20160816;
        b=K0/x2k2OzzXdTnwtnH9SAi/4oV/QfwuUYfRM9/NcHuyS4UvfZyDlYru5jOKGM33Wdt
         VLkZecYVQsyZNgh7MGDKXsx6UBnwH8QAblFzCOpdAJIr/eQ+X07IKa/qCDqozBlFLHA6
         lAR/TR49Ct3vt1joSp4Zt/WiQ6tJ9tj5YlXySkCoP09p8EQQnGondjmGz1SaS04ixdG4
         mFDRO8jsj0Cuyt86JVJ+rOtrx8U2qjB0RnyF1+idGw6Dne0Xs9tTE1FmL7wLAz7BmLyw
         REBjVJbtlIX+CkdabhMBUEvyYC8xTJ0+dIahzTBueHH6DQH2pCBGmsebbI+gMHTQHDxC
         3KrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:cc:to:subject:message-id:from
         :content-transfer-encoding:date:dkim-signature:mime-version;
        bh=gYxdg6Ywm1j2Wqe+IHnSaRNfCJl3qR7KAJAGDMcZWC8=;
        b=T9bMI1UfsdxkqOy5Ucg3T+gEOUTKBwbq4lTqneGEjh9TQhDeeMVd3IcYYdpGKnPENM
         D5vKqQBFlOmEdMOjzwjWkJSsX2WXKpvph0Qj/XXJVpoftxhnbvkmztV5pTlsN+1UPW8L
         5zIeItqm9m3Tu1Zzx9bxN1F5pvaW+yokPaATR6SbrpAERAt8E+Llo6Kktwjh3nCRFY/h
         TiEcWfAxfFXr167Am/RKfnaJJOQaV4T68YFLg48figwpM1+HGwBXvEYBh9w0oKzM5YH4
         YXA6Vtor2VqQHmDpShSxYZUUfh1zNBFc7lXM2LWuv5eGeGVdvTba0kI235SdmS350x+G
         fg/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kv2pu9RW;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id l5-20020a1c2505000000b0038ebc691b17si211157wml.2.2022.05.17.17.39.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 17 May 2022 17:39:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
MIME-Version: 1.0
Date: Wed, 18 May 2022 00:39:53 +0000
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "Jackie Liu" <liu.yun@linux.dev>
Message-ID: <3f53409c2de1dd22e42dffcad57f3603@linux.dev>
Subject: Re: [PATCH] mm/kfence: print disabling or re-enabling message
To: "Marco Elver" <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
In-Reply-To: <YoOKC8oE7fbsWsyS@elver.google.com>
References: <YoOKC8oE7fbsWsyS@elver.google.com>
 <20220517111551.4077061-1-liu.yun@linux.dev>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: liu.yun@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kv2pu9RW;       spf=pass
 (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:863f:: as
 permitted sender) smtp.mailfrom=liu.yun@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

Hi Marco, Thanks for your reply.



May 17, 2022 11:42 AM, "Marco Elver" <elver@google.com> =E5=86=99=E5=88=B0:

> On Tue, May 17, 2022 at 07:15PM +0800, Jackie Liu wrote:
>=20
>> From: Jackie Liu <liuyun01@kylinos.cn>
>>=20
>> By printing information, we can friendly prompt the status change
>> information of kfence by dmesg.
>>=20
>> Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>
>=20
> Personally, I've never found this useful. If I want to get the current
> accurate state of KFENCE enablement, I just look at
> /sys/kernel/debug/kfence/stats.

Yes, I can get the status through this file, but there is no other place
to indicate that the status has changed. By logging in kmsg, it can not
only reflect the status change through dmesg, but also be recorded by
programs such as syslog.

This is very useful for me.

>=20
> Nevertheless, some comments below.
>=20
>> ---
>> mm/kfence/core.c | 6 +++++-
>> 1 file changed, 5 insertions(+), 1 deletion(-)
>>=20
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 11a954763be9..beb552089b67 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -67,8 +67,11 @@ static int param_set_sample_interval(const char *val,=
 const struct kernel_param
>> if (ret < 0)
>> return ret;
>>=20
>> - if (!num) /* Using 0 to indicate KFENCE is disabled. */
>> + if (!num) {
>> + /* Using 0 to indicate KFENCE is disabled. */
>> WRITE_ONCE(kfence_enabled, false);
>> + pr_info("KFENCE is disabled.\n");
>=20
> This will also print on boot if kfence.sample_interval=3D0 is passed. Thi=
s
> is ugly.
>=20
> We also have a pr_fmt, and writing "KFENCE" again is ugly, too. And
> adding '.' at the end of these short log lines is not something done
> much in the kernel, and also ugly.
>=20
> So what you want is this fixup:
>=20
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index beb552089b67..de5bcf2609fe 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -67,10 +67,11 @@ static int param_set_sample_interval(const char *val,=
 const struct kernel_param
> if (ret < 0)
> return ret;
>=20
> + /* Using 0 to indicate KFENCE is disabled. */
> if (!num) {
> - /* Using 0 to indicate KFENCE is disabled. */
> + if (READ_ONCE(kfence_enabled))
> + pr_info("disabled\n");
> WRITE_ONCE(kfence_enabled, false);
> - pr_info("KFENCE is disabled.\n");
> }
>=20
> *((unsigned long *)kp->arg) =3D num;
> @@ -877,7 +878,7 @@ static int kfence_enable_late(void)
>=20
> WRITE_ONCE(kfence_enabled, true);
> queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> - pr_info("KFENCE is re-enabled.\n");
> + pr_info("re-enabled\n");
> return 0;
> }

Thanks for you fixup.

--
Jackie Liu

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3f53409c2de1dd22e42dffcad57f3603%40linux.dev.
