Return-Path: <kasan-dev+bncBCT4XGV33UIBBJNYYX7AKGQEQP2GYEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FA992D4EAF
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 00:22:15 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id c12sf1754977pll.12
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 15:22:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607556133; cv=pass;
        d=google.com; s=arc-20160816;
        b=V4ybeRvDma7nUulbybEvE2pR5F3Tlvxk+9AfFuF/7VHqFAHw2pfliHu6Wu5ey/nXx2
         FbFrtRRab3crwY7gBY9ZOI4XSlEGjc0jjjpafo5mdr/nqC/zlsW01t0waEpqlu6U7GS6
         BNYvPVGxpXEouJOf1DUSbzlGB+8XmuV6pW6cMWn162cqQBzofdOEVIo/wQIpIMFzBfIZ
         2i2JNttkEG11o7N7N0HXCdhd+oduEFkL1II+PmauIiRtu6OaMgyVuUL8B6kxOWdC+Na8
         1oX7fCwZ3fNXZ64vGxsxSb6YN5Uhn3py4csop7OKiX/eFVghXt+Nf/WdIyyhVLCcMY30
         EDEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=SASTi0NzwX1Y9UV513Uqn4FEWYctSONuPlXMhgmWSaQ=;
        b=IjBhA4ruPfWiHaNyqeNZWP7JepXs+X/GJLVzK+UNcX0cT6r4Uhb34pqOQQGnEdDQDm
         PIv8nSuEMYhGaONozT1kSTp7BtD74EuYpVoTLggY5h6WWHFLBWsQE/khiXe1LAphI8H2
         IQ+IyOIe6hjxk2kuHGA1JbtLFjxFBkLgE5F283ro3TeOWPYA8Jd9jkUAoel4Zplqdz6W
         QezLl7njSDgBNviAUlY53P6/Ojmai6Mzx+ioX4C7KgZac9x1Vl1XH7CzXQC3IiWi6lrh
         MIF+BKTZ+YxwtIMf1nwCkN9Rlj23ajM7IIceOSLU9w4pVrcjBuasjF0VHZCEdv7JJV6z
         w8gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UQ705txG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SASTi0NzwX1Y9UV513Uqn4FEWYctSONuPlXMhgmWSaQ=;
        b=d46M6wRUTiU1LZrvNWYJsr0RJTtHRUDgyYB+uTKrB3mwaTKQk3YS4BQcr1FpZ8Ph3p
         v4fZF00XIVlVNXzniamYZPeUNqPWFaV6MC/8IUh6gNvI2Y/jbVc5RaIJ8kF83IzYovWh
         CaK/lVwpUth0+Od3lqxEZrKtZ6GaavZFEzOnsxpoFzZaSWKYYQFfG9gDxat5QQwLQ9WK
         nKR6zvyHMrsP2lYOAtni6cChzaD+yQAdj+bN/dyK8oUnBq8UDKy9Ko/5PooJGJpyGq++
         qYv5c1wEnEnARuo7GWJTomkKc740eMPXRyL2UL/lexQbs8NJIs1OUDIyizbF1P1HNUp7
         95jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SASTi0NzwX1Y9UV513Uqn4FEWYctSONuPlXMhgmWSaQ=;
        b=lt7TemHzj9oKqDYVqeslP/C7f1IHoIVqvNBagxpZ2lqtVrJtg1KdwdG7QY0tvziGET
         iX6SK42PAubcBJcp/dh0NBCmDWGJtnsjv7V3kZ/V/lFBYnNTL6cDyAcG7OZn6VgHORw+
         edG2Sl49UVyFI3T5j+dSR0uI8EL4gCa0gABx0lqGSzv5HYZHkVoraMuPuHuRnQK8RD10
         xqniYJ9qM/KfmRZS1j2rS0P41DkU7N84RIav0lTsxcTo9zZ1wMAPuzebdxDs2s/2EKi4
         Ge+9I9QJ1q7uVdJFjZo88AU36asvZYERfLQQe7djhy6kVPZdF8s7OR/Zd9kS5IscG4m/
         4yAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/6FQAfL3sVsMbHhokmleUKTevMY+65kE8ZBNcO/2SaUW4v7l/
	B79HwNnxzQuLjXk2FDnFqOU=
X-Google-Smtp-Source: ABdhPJy/VLTWod0BbkoO1ulkKMUtoP9oawsfQl08RutmE97wHNrYwOer/pUFKjFraH23btpcOdRN+g==
X-Received: by 2002:a62:2947:0:b029:196:6931:572e with SMTP id p68-20020a6229470000b02901966931572emr4310203pfp.79.1607556133244;
        Wed, 09 Dec 2020 15:22:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b086:: with SMTP id p6ls1510134plr.7.gmail; Wed, 09
 Dec 2020 15:22:11 -0800 (PST)
X-Received: by 2002:a17:90b:1987:: with SMTP id mv7mr4388504pjb.66.1607556131476;
        Wed, 09 Dec 2020 15:22:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607556131; cv=none;
        d=google.com; s=arc-20160816;
        b=y25rDsOHkimfyCXwh5Kb0Fiw8woE1+p2laClgg5plpvvWD+8fxalX6C396Eqt4ugEZ
         aRxxlaJX3eeS6dGItGKdNNnhCe0DEfny5oq9w8OXLP97XEp+tSg0kESv/M4X9EyWaqNH
         d+bAu62LKmClGxvkEdRiaZJ6nAa+8IWhs7ICKjxcIiIwOcdkK2NnXTXj0UykDgMsYbmf
         c/424n2SZrZTw0PU4BllrukYbsPWsqJZ/ZdBp9KB696gxuoePlbUpgFHznsSghRUq8N4
         itP+rMPCZHgpGcx2jxpc8mXnmG+j7UtTTaLSTeb4zOM8eKKiedYTaxqIJswSvYJ+uR2n
         5m3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:dkim-signature:date;
        bh=Os3bL3JUMsypdS4/Hy+3tqd92dFFxX6RL815uKEU1+0=;
        b=hN/BdjVWeP0wFaNXW47a7QnA7vUB2Ia/3Dabtw7BjusStaMEiaKm1BZBPrElo9j5L/
         lNQKSVVrvE81yIe0gPjqgGOaIK6rQ3NF6z5qHfsYedmJ/A0LqMS5rI5beTsnL1De3Fqi
         6cFeXwe0jKPFWUBLl6ksTCSgtUk5J9qXXo1KgWzjki0tiEDYIDzjZD69UTQrPTg6tOLk
         SQ7JWaiZDZ/3bZqNU/isXqXgQ3tJuAX7EWvbZsoHM+O78i3CKYfCVF9wKG8K3DD59WE+
         ZaA4eQWeaAmg/KvaT8GVaWw/q4U1wgkf5821Gg38E8/tP0NUQwtdvxgtxamZKZ0UHa4+
         oDpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UQ705txG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y68si275687pfy.0.2020.12.09.15.22.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Dec 2020 15:22:11 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Wed, 9 Dec 2020 15:22:09 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Catalin Marinas
 <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, Branislav
 Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, Linux Memory Management List
 <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH mm 2/2] Revert
 "kasan, arm64: don't allow SW_TAGS with ARM64_MTE"
Message-Id: <20201209152209.7af1e9fbe1bf523483d29539@linux-foundation.org>
In-Reply-To: <CANpmjNM9suHQY-uQN9g5h=Vdv2wotDKNdcnHM=-RTtEb2sCZTA@mail.gmail.com>
References: <cover.1607537948.git.andreyknvl@google.com>
	<a6287f2b9836ba88132341766d85810096e27b8e.1607537948.git.andreyknvl@google.com>
	<CANpmjNM9suHQY-uQN9g5h=Vdv2wotDKNdcnHM=-RTtEb2sCZTA@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=UQ705txG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 9 Dec 2020 19:51:05 +0100 Marco Elver <elver@google.com> wrote:

> > This is no logner the case: in-kernel MTE is never enabled unless the
> > CONFIG_KASAN_HW_TAGS is enabled, so there are no more conflicts with
> > CONFIG_KASAN_SW_TAGS.
> >
> > Allow CONFIG_KASAN_SW_TAGS to be enabled even when CONFIG_ARM64_MTE is
> > enabled.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>

Thanks.  I simply dropped
kasan-arm64-dont-allow-sw_tags-with-arm64_mte.patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201209152209.7af1e9fbe1bf523483d29539%40linux-foundation.org.
