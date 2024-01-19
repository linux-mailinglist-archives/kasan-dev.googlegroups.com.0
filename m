Return-Path: <kasan-dev+bncBDW2JDUY5AORBF54VKWQMGQEWL5DSLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EC6D832CC9
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jan 2024 17:06:48 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-558775f2401sf20109a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jan 2024 08:06:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705680408; cv=pass;
        d=google.com; s=arc-20160816;
        b=L9gMumCFpsCd6OIdROMzAU+s6o05Gytl9RqZJU1ym7TpP6/wZKa11uxJAYKPSwFeWH
         ojQVN1Ezv1rc/1zeEgXYxgvtRlER+ijWjmclrMrrxBjji/HMD5Uw/pN+c6uCqTgLglND
         SrtsBRv5yeaTQxTN4Nn6SeBlm4h75yq2xBOOq3j8HyxDrM6IVTwpRAHKcPIc1MLlaYTQ
         0GTDh/bMKvaAmcCL9UEePgJy4WDCdUKDVadRbbngS2fg3HFWHt+hw9HVAfM7K7VZ/sdz
         F2v7WimoXXYrs/ILtQ4Dz3xhwUkj5OTfT0V58sLWzc6SoawXFB/ztc6SjAWHI9ThOllY
         yWKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qhSRfeg5vo91m/gPKZKKv1v5I+9vk9wawux1r5BcW7Q=;
        fh=3UnUE0ZTm9J0Dl+1ts54ub7IuN7aYEb5HIKEYMj6vAE=;
        b=G94dWkyAqatO2D7LX3zkbeX77IUQGQqAi/rskwNPOoi8MRQ9HrTXyxJt8cjyDJO+o1
         aBE/YaslWQiLHqm1jkwcN5k4HQ2UV/umY/fRaWEY9zoyEZZzky2sRezIzCJSADPIN02+
         35hSifdlhuY+gsF0i1eXCPNPMiuBqHzMVNwXOidgcezK8ApNB+uIpuqtVMkeW392Modb
         MbLLz8qnXlO73QGi5t2bSMq+NgkhgpAzXP/r4grAuhvP2GdUuFNP2Di5fvOaqBf4MEvd
         fAt9nqOYe/y0qE4fPkZD5R383MCij2k6qadP4KN4intcuhP1BAGsQFZwrDumylmrqlXe
         1ZAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Fx4RNqdQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705680408; x=1706285208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qhSRfeg5vo91m/gPKZKKv1v5I+9vk9wawux1r5BcW7Q=;
        b=dHbsjl3F9UgavLm/2F220R2xUnlAtxQxsWXaY07TsiYr73JD/Cerh6pK3KQy+8eXrL
         QvDwzqpci05rsIaN8pwfcatmsKaSvtL2Xe6e8suwMA9SylJrmtkSCgeMkDft4K1cWZ4O
         nrM5JtNG7/2YQBTMBz+ybGfXJSzxymapb/1mBVfaOxvJ58ISSYUFpJ8t+AYGs5eBirBe
         WfEii9ghovJEQJX3Ah901OBmv2ot2iKruVRYK/2i3CK5q/NjAIi1mZwuosTnL4FwkNyU
         03XfKSXPC5zMe5suQJ4xAWC/8N7UUJAfeFPuE7YuFWZ9j3WBZr00xewSWPsP3nlfVu4m
         OItw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1705680408; x=1706285208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qhSRfeg5vo91m/gPKZKKv1v5I+9vk9wawux1r5BcW7Q=;
        b=mdxe+m8FGA5bUCu+iOvvAOZ1DPKchGvWDluWJEWBaJckGApY3tPEQWudVMv+IkoHI+
         RlZWgWfzIAcpxee/bexp9DH8Itl6CXajfGEU5jz5Vf4kOIhYFZTm035w//NrR7FXHPgN
         rM/2dYaPDb89NHyBnrOZiDbrpuzVMrp9wgZz+ZqMYyUFF7kNGFNyPeczV4+XAtWQfwbn
         FAG9uWkdF3tKMNcvcwwFRRCX3zo9+V9v1Iv6aA8nixauo3PK5o5dGYkc3XZijWCrp6o4
         f9Wwuu7FP6hu2UXt6CEib3t3TrEmwOYoUVPwoGxfO8GRsVWvGKsQzjvPoIh6M5fcjiKD
         QS4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705680408; x=1706285208;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qhSRfeg5vo91m/gPKZKKv1v5I+9vk9wawux1r5BcW7Q=;
        b=tq2V0ToWDvhYe9rMyHSybxaDan5Zq7lEmEyG9bvwAPCzOPb3jf6ARcFZuitlWAqXgm
         RWHdH5hz1Fm1pfKmix8cuvYOMaWwaHV5PH5T0HLAtcdKQbC6zyfqjJP56oxuDpUXq1+U
         AEu807HsdPVDYuJHZaQhGSxH46TsXxxqchafVfvr/Y89BUU9hCDmJku+h81/kBB/AHxl
         70wpl8WxacEyzMOa7ygR8MAZNJm4BINdXFGHhe2XR6DEc+9UYOQRhFfTlCOuO+ojYcGH
         RsE1z5FEn8NlI2Cqivd840T9LTIKfR83yb1vt016ShOOqpAm+5gOrvXWymKTDAYuC59K
         J87Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzO2vn3mTvO9Uod/HDpstWqP4ogYhzUGdOsIphUWW2T71WuJmGx
	Ndxn12XG31tMmbDm9Ax1ihLeoRPv+PDOJxr/sZeJ9/P3fOw3IUsq
X-Google-Smtp-Source: AGHT+IGOQgwIKFzoK7g7XkDq4CxNlx7NAxqpctyXi7iVBpGBF3lrve9IV6SwoFq3KWB9PJ6+AmGb6w==
X-Received: by 2002:a05:6402:220f:b0:558:8016:b347 with SMTP id cq15-20020a056402220f00b005588016b347mr141387edb.5.1705680407315;
        Fri, 19 Jan 2024 08:06:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3222:b0:559:fb01:b589 with SMTP id
 g34-20020a056402322200b00559fb01b589ls204172eda.2.-pod-prod-07-eu; Fri, 19
 Jan 2024 08:06:45 -0800 (PST)
X-Received: by 2002:a05:6402:318a:b0:55a:5f79:111 with SMTP id di10-20020a056402318a00b0055a5f790111mr622729edb.7.1705680405548;
        Fri, 19 Jan 2024 08:06:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705680405; cv=none;
        d=google.com; s=arc-20160816;
        b=HOtEjhmcjAPA1/0ZCpjJgQ607aYiSvPYJRiBAtkSed2wLjjmf6y6nSwW1FvkUlA/RP
         kiGghe8HaZfS9sCQcvGeJUU6KWmgTABn/hbHARbyaRWkHZUNf2f2hbOEH/Zd6EZ8xYCg
         J/q1VIwls9doI1VHW95SDgdWk80y/Ua3Q8hGVXfelCtA6w7goq4BarSgRVhPWcKXPwrI
         arnbMCWXhpWJH86crHqrnXtdObrLVfb3NTvyOPbprh3Rb6TjsxqbmRm3Bvrt5pHxIEVg
         ymTz22Otua4mgEctaibFRVIEQRMMB9u2eLxeSz41ftIJboJf2IzIHgAXqPLm5SzIxXSl
         xU0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Zg6dkyC8947sbBRiAX9OoM6KBxuvm6ZJENihVQtKCUA=;
        fh=3UnUE0ZTm9J0Dl+1ts54ub7IuN7aYEb5HIKEYMj6vAE=;
        b=aOEDZSb9t/eZzjZy6X2XnzS/J4g1R0e1ZxvPIr3eugQ+jEmYeDs5aDkgw0o/YHCAFi
         MRSYz/ajHIgyj/KDbYUlSVv/47dXXtyItJTB27bVzCF4A6VYt7qqke5slOZ+v8YLIA0Z
         2TLr0aTKOfV9gr20UyeRdme0OQQjIeTSHTb5GHPMfaZICxlc1L07Exo7gpgkR/7UQC2S
         fHWvvQ246RK7aM7Mcf+jeD28je9N5UF0Ae6jiKXXp2t/Iz4aCtoj6cX1p8K621TGOMzn
         K2NEdPDC8ILNS/Db0mYE+2D+pQaMrw2xTPUujuejXUW4l1Pdk+1uJXucySmY8bdkyexQ
         qI9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Fx4RNqdQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id a90-20020a509ee3000000b005533f8f54a2si975848edf.4.2024.01.19.08.06.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Jan 2024 08:06:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3392291b21bso499734f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Jan 2024 08:06:45 -0800 (PST)
X-Received: by 2002:a5d:6351:0:b0:336:ebf3:b8fa with SMTP id
 b17-20020a5d6351000000b00336ebf3b8famr1287798wrw.83.1705680404926; Fri, 19
 Jan 2024 08:06:44 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNOnxvGNtApe50vyAZLmoNbEpLeMiKHXRuRABkn6nhEQWA@mail.gmail.com>
 <20240118143010.43614-1-lizhe.67@bytedance.com>
In-Reply-To: <20240118143010.43614-1-lizhe.67@bytedance.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 19 Jan 2024 17:06:33 +0100
Message-ID: <CA+fCnZdVVhx-sNU36A1pa3dJkE_RyYjdJU-PZQf57E42GWO46A@mail.gmail.com>
Subject: Re: [RFC 0/2] kasan: introduce mem track feature
To: lizhe.67@bytedance.com, glider@google.com
Cc: elver@google.com, akpm@linux-foundation.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, lizefan.x@bytedance.com, 
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Fx4RNqdQ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
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

On Thu, Jan 18, 2024 at 3:30=E2=80=AFPM <lizhe.67@bytedance.com> wrote:
>
> Yes I am trying to add custom poison/unpoison functions which can monitor
> memory in a fine-grained manner, and not affect the original functionalit=
y
> of kasan. For example, for a 100-byte variable, I may only want to monito=
r
> certain two bytes (byte 3 and 4) in it. According to my understanding,
> kasan_poison/unpoison() can not detect the middle bytes individually. So =
I
> don't think function kasan_poison/unpoison() can do what I want.

I'm not sure this type of tracking belongs within KASAN.

If there are only a few locations you want to monitor, perhaps a
separate tools based on watchpoints would make more sense?

Another alternative is to base this functionality on KMSAN: it already
allows for bit-level precision. Plus, it would allow to only report
when the marked memory is actually being used, not when it's just
being copied. Perhaps Alexander can comment on whether this makes
sense.

If we decide to add this to KASAN or KMSAN, we need to least also add
some in-tree users to demonstrate the functionality. And it would be
great to find some bugs with it, but perhaps syzbot will be able to
take care of that.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdVVhx-sNU36A1pa3dJkE_RyYjdJU-PZQf57E42GWO46A%40mail.gmai=
l.com.
