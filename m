Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBFXPYDBQMGQEDN6OFCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A8320B00E3F
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:58:48 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55a04ed9c19sf40286e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:58:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752184728; cv=pass;
        d=google.com; s=arc-20240605;
        b=M8WOh4cVRyeKYa5Y4jsE1cUrWduqZIkjLBFK4IpUFaEapS3VyLRUk5jEqYO1oUr4Jw
         QWTL4d1NUrUNJjKyus57ZgFmTPOnZS95Pv0h2f5/gHssPTRQvOLodqnqnxL83B9c8iAe
         dVxxinEefN8Mpd4XgpoRc+Ihw0w2kBQLi6tUKIJ8ytYPv6j6ES7xnaUfguCHuw2qUg4S
         /9zixrP7yQY39Bsau3O5Seq8ve1CM7bhM1ZqlupOAppdDV82jX+8XmjVzyJmwyHTw7N1
         OpkYEmEWibMMgbNfkF/SexsLO7TTJKsUF52i/IShl7FF5WF6WI3UTTujqP1ogT/Omp7v
         /zBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Zjc6gfy+taQdgPQojXVVmw5TF5XgvFbJOzh+ACWskOo=;
        fh=U8zPbJ91wou+I4N6YRNL0dbUbsXA3nFoJPqiN7gI4S0=;
        b=caTAZu0MtjtbpYnR8UkYJUWIsb2VdBs7PS4Ne+uXxxcqKyLK4fVJ7xcdx8iYrEWiGK
         O+sNsib0IWtq9ifT3Eepdkm+Nccq0ofC+b8OoRnYgQeIEpyXxfz46OCGFztkg6GzAKDU
         FMDnqwzO7fn3uLuhGTe7mNSl/M92RyPtonlmo0RWHIjmLKE9MMv7iDZeShbT+KNm9TX2
         NCk/e3SnWaWJkRbuC294DM98nyGXDiwXc1VxSg3iAAInKlJrS7hWE8P6eqOY7Ih2/KNB
         oz+QpCdZKjUGa9rWsy97anaqcqOEZG8sH16kn4AQ8Iwde3aflUoNVg5rxOxl6dzx/u3h
         M3TQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=gewVzeqQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752184728; x=1752789528; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Zjc6gfy+taQdgPQojXVVmw5TF5XgvFbJOzh+ACWskOo=;
        b=do4O8VofUioB3fHqAp0ptvr1y93nJWbwQGYYdPw9tWn3UmyKUyDj0huSRpF7aPVIj6
         nlM8GEyF7VenUbNpQrKRzScf4l+EfLd3a+P5ugfJC1ys5FFyZ72jjCfAl3Ff+9TyDeu4
         VqvI4wyxrLw2+PJkgNPrs3S2MZIJml1X129GtAirQTNByws4X6CC17Ym4dYWCoxhBaDU
         RZf6EyGGaVT3vZdHpXwAv56REYq+NZ3kdicU8LwJy/wNz/KFlDdleBi/alnl7QNHdiIE
         CxzjX4JeDU0kVLX08rEgb76o8U4fGzWmAcXNogSX1KKMWS6Fo3Etu0D46l7GMipKWTjZ
         Q4Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752184728; x=1752789528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Zjc6gfy+taQdgPQojXVVmw5TF5XgvFbJOzh+ACWskOo=;
        b=Jg1ATm3f6UeuriklSbJ13zXvs4zsztqYa2VFvMbk+dA8kcs7WXJx3hrja/4Q7W9s2k
         wrr1biHyjFBBPgxsgwg9KaLfXb5j3yTv40Aw/UyFVedFMPJxMkZhQfUcpVSH4EQe5wBc
         nPYWQAcjy4S4iP990DZIi1RCJ1yfwWgbXnlnMm6yQlwEwsbdF9JB54AT/c+eWeqSCzqe
         1akXgKvU/4CCxbg9unyaaXinDhufm7RPI8KObyASwjjTqDStMVap2yx/Jl++fMCn8KRd
         lAAhxrCG8JKQPnVUV/SdFDP/1ZYYF3m0FKaohjykLVD2f/YJfGO760Bf7PYD6qbzXwIQ
         KBcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVpAy4RgkepzXAc3WLV+DnEc46X3BsZHM+7fdCp1sjW8oCi59ILKdJcTtrpB7UjGz7cA921vQ==@lfdr.de
X-Gm-Message-State: AOJu0YxbLgWpkM2L/Xzpx7Lh+KlP75/jXz0I56JZCCBdG9PvjAbVeWsv
	0X+Mkf0fLYTgDE4qJTxo2gIQXNO9BCE5gGZFxeC3SQ8gJh/5XxQznJ+Y
X-Google-Smtp-Source: AGHT+IHWDmhpDTd3u20S73n/Ryx/IsLhGWKUWed8xfVHJ3HdccZpKg0S0TuzUnB9hkJz5OvmDFowVg==
X-Received: by 2002:a05:6512:1115:b0:554:e7f2:d76b with SMTP id 2adb3069b0e04-55a0465814fmr125334e87.56.1752184727488;
        Thu, 10 Jul 2025 14:58:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdN3qTHhYVQVKQey95W4rSCz9t3zaaeyeYkH2GHNq8Cgg==
Received: by 2002:a05:6512:630e:b0:553:67a9:4aa1 with SMTP id
 2adb3069b0e04-559003a8732ls335182e87.1.-pod-prod-09-eu; Thu, 10 Jul 2025
 14:58:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVj13otj/5uvZtc2Cj5hptugzz5TxTZiBz53pLJqbpYpEhAbvAS+zD+mK4RIWBidS/Zq58oZ2qBcNQ=@googlegroups.com
X-Received: by 2002:a05:651c:3252:b0:32a:7a12:9286 with SMTP id 38308e7fff4ca-33053477958mr1670681fa.31.1752184724030;
        Thu, 10 Jul 2025 14:58:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752184724; cv=none;
        d=google.com; s=arc-20240605;
        b=MCn4hay5wNVO/WvlUOqAb0Gt/gERN7i/u+bC3qRz68Tkn0UX/41t2ASLfjO0YM/O+g
         Fr+ZfUuGaSVxmx28fe71dOHnxNnfsUhmQqAHm0SEuzguA2elC6AIprDt+H6GLpHnSRq8
         i8gNJCYB06Q5m624F3dE3hyQprWLA1vvY+6Kj0l1EErvQPPYXhtCWsrtME1HdGU9RvRa
         WiC9KAPuYc9Xl9rXmIlI2LDMN+62KU5TQYQT+ypwUSmzFkEdpUwcwa9QCrhj3tuoWPFH
         bDWGTZbRtTPBWdnLlYUTJgYTZrNphjfBiDTD5l9j4vMpsv8MA6mDEb5T92peuC37myW5
         tySw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NOhvg1l0t2LaUB8HzcyN7Tq+OVNAbmeCuPM6bN+kiYw=;
        fh=a4caM1NHJUw5qFHXn/RcbqBkC1reS8td1enaFZqreJc=;
        b=GafV3WEzTEqL4xv3V0JHq9pbYGEWcpTFFJK42wo9NoPasolrjo2ifMfObbuZrO3Rvp
         vVoN7oV4OSN94A2Nd1FWinH6bis5NLl5ksj7NtMTegshQ0cgRxVCcAKXKiEa0yv9BNbB
         DWOC/MMXeRWVEtu+h1h/KG8WWr5wmS6D7dubIZcqcFFnNzFVQPP1xcaIMKXlLLuDXb+B
         31JXVkY6UVT4LQ2Gw6UkYG0nJVMLBggXLtW0ky4NPXVjgd3f5uBnX+mVz4afPjBe0mGS
         r8KFufmfZzGQdgKLv/pkAwUYwgy+qaDYI6LzpTINoSt9uGNiPEKSZ8Xi0teoMWhm3Ljp
         ol+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=gewVzeqQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fa2932674si698551fa.1.2025.07.10.14.58.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 14:58:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id a640c23a62f3a-ae0d7b32322so224890566b.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 14:58:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVGhlVBfSp7n2vmJ28mYH1LgUA1hAlfFsPqmWRhlwf169Px+m5IWI3OHz60XpeS1FCf0DYnZUBFoRA=@googlegroups.com
X-Gm-Gg: ASbGncvpLtn3lOBMX7tTaIsSNybiM85J2JLdwjVwHPn6OUqq76bBnjwJhqrVUVs8h92
	Z3IoJb0sVtu+JtkK87WSR486GGG/0OT5OqSnue4i2JPaDyqlg+AxCIay6uN1mtaKWyTol0GivLG
	K63iYiy8NfQ9FYjxQvAc7Q9scdutHPSjfzs6Ohb+b1RWEH7qmvcpHXWKTl4eqEWJ5qCL6NQ/+ye
	U1f91w7rQ13TTI87UIVKhbSffW+cgipRXRQs/gghacqtZLwv8p5A5j8AZIkhSMqgrJuJD11+0xs
	pzo5ttFii2n8oXY8EQI4lDeSYlJ0bkBHy5fHPHfpNcMLuJ4lXZG7P9BkBBuytllvLED1QWAIY+U
	Lyc0CQZX1rtNwLbPZyYkNIy63K6h3T0yld3Vs
X-Received: by 2002:a17:907:1c1e:b0:add:f0a2:d5d8 with SMTP id a640c23a62f3a-ae6fbf41002mr77208966b.11.1752184722933;
        Thu, 10 Jul 2025 14:58:42 -0700 (PDT)
Received: from mail-ed1-f46.google.com (mail-ed1-f46.google.com. [209.85.208.46])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae6e7e90a42sm193306766b.27.2025.07.10.14.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 14:58:41 -0700 (PDT)
Received: by mail-ed1-f46.google.com with SMTP id 4fb4d7f45d1cf-607cc1a2bd8so2373071a12.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 14:58:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWrBrop+/ayZ3FGymn80k2S5U6Th4NR6wB40MmZbzoKe80slEAfTPWFniJY2Lv+ez4Pmn4ySgGjsuM=@googlegroups.com
X-Received: by 2002:a05:6402:289c:b0:607:206f:a19 with SMTP id
 4fb4d7f45d1cf-611e84a9aa4mr389972a12.25.1752184721009; Thu, 10 Jul 2025
 14:58:41 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751823326.git.alx@kernel.org> <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
In-Reply-To: <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 10 Jul 2025 14:58:24 -0700
X-Gmail-Original-Message-ID: <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
X-Gm-Features: Ac12FXwFBMXaxRHdcUswF9pkpuvbALmMtsHBeK-c4iMg5ugUB_Hn2l67aUaOXFU
Message-ID: <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=gewVzeqQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

On Thu, 10 Jul 2025 at 14:31, Alejandro Colomar <alx@kernel.org> wrote:
>
> These macros are essentially the same as the 2-argument version of
> strscpy(), but with a formatted string, and returning a pointer to the
> terminating '\0' (or NULL, on error).

No.

Stop this garbage.

You took my suggestion, and then you messed it up.

Your version of sprintf_array() is broken. It evaluates 'a' twice.
Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
argument.

And you did it for no reason I can see. You said that you wanted to
return the end of the resulting string, but the fact is, not a single
user seems to care, and honestly, I think it would be wrong to care.
The size of the result is likely the more useful thing, or you could
even make these 'void' or something.

But instead you made the macro be dangerous to use.

This kind of churn is WRONG. It _looks_ like a cleanup that doesn't
change anything, but then it has subtle bugs that will come and bite
us later because you did things wrong.

I'm NAK'ing all of this. This is BAD. Cleanup patches had better be
fundamentally correct, not introduce broken "helpers" that will make
for really subtle bugs.

Maybe nobody ever ends up having that first argument with a side
effect. MAYBE. It's still very very wrong.

                Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h%2BAE0PY4kag%40mail.gmail.com.
