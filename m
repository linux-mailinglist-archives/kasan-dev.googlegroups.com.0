Return-Path: <kasan-dev+bncBDW2JDUY5AORBPNJY6SAMGQEDI2T6XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 429D47371AF
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 18:33:03 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3418f0c7ef2sf38322695ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 09:33:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687278782; cv=pass;
        d=google.com; s=arc-20160816;
        b=jm5qCCZzR6HLDqkw7DVGgGwTCQDMLNyZnhP7L8DKbJsfIqNX0rz1N5Ik64qj6Ftu6M
         98tuAMIoHBYx9QSr2VYxgBSsvt2eLvmQ6WPVMsS+WQjUE348FbaLVZ8Ue/JRcZOwAfph
         p98rN4GeK/sjHiwgw+15BnzNep/SYo31pK6T/xS0axq9SPzvcWr6XSOHi+ceijYVOJi7
         q0It/xHtIDdYZn1odkmtuAlTEepwx8tt6gb9zeRjbukLGsPjQd2YIp3xpECU3aC1qZLP
         zQYH54ehth3jhdkvhzIpaxB1cjEbfph7uHza8n9j37VNFNIf+Z3oTXz+Zla69tj0v6/b
         XOBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=AKf61092/rwaAg1su3PjYbmIsldHEjPTlf5Y8SGawzA=;
        b=mqcOEiRM6XtE6wphEId5puVVH9zyewwq5+MlP9FgjylzPpO114z2KSm2XxXOakFNmk
         LP6y6twGyDGww9g+oY5jMdFnq05xukq9tRQAxmToQcdSWVLrhZO5kZ545R9x66glWRlt
         ej9Sw0DY8eM2lPeAzoIaLj2c5+TWrb8vStm7Y25UMKAO93VO4CNeFCQ9NH8Fm6ANat9y
         V2hXiMm7P28FHC6MwBfJaDdJJrKH+9OP5vxCPBW0+vDEubP6Dh4a0wgjPJHQrHTB/6Y6
         BrwS7LdRBHaGr2ODhsWMCWWs/che2MHOpFIZ2pXf1mmMrE3UQ8Vowq5Yez/FGelwxBXc
         VTTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=o31p5LIv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687278782; x=1689870782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AKf61092/rwaAg1su3PjYbmIsldHEjPTlf5Y8SGawzA=;
        b=doMFMbmNZT5PQpZlUEtjEi5mAFsoc/zUmKlDpIQXZeF7zx+Oh+2e12YA1egOOLDroB
         jxtSrnFg4QOGmmDH0WBlUa6KXpX0bu5A6K7dGTtjHAlrb+wxZwx57WuDdhId51efksNc
         8/1x4q/Ayhc63vF4iHBmr5Co+UoP9fqtVbt71KXuVxm5/5ilXEDc4Jzftv4/L5AXFQvz
         1VTPngTcflzDb/l2f/DEZM7Mc5O7mYNtHz3xKWLvtoeZ3Wylusgxaoovk5D/zWdYpdCD
         5kjxWd6OVq+s+ej6f7KX9E7msqZV/9Mh7pCcNlhnga1YMQgaPdaSww6PlHvWiw59cXkE
         RL7A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1687278782; x=1689870782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AKf61092/rwaAg1su3PjYbmIsldHEjPTlf5Y8SGawzA=;
        b=Z6IXyzVjrNdSyDj2rDaUr9KtptpXsc7Mk3fhp+qu6SEZbMpvZZqcAaZGcGIkauU2kJ
         WtHNI+wHdXxYETt97djPgTBhUBkyjnRoV0yttXYI0AfkHMxtbBcqakLtbpVE/QJoL1J3
         B2pVeYH0CEgi09EfS40epOtonXZTD3GSG1UwBlVqRUOBxlKOwWyR+iVXEuVDDWXXestr
         YJUSp/VK1DNfP7aODEunafwBVxXge3XtVzNbEcLuehs4RkwPsbukAgdmb0pUYxj4W7tF
         cDnjghyFLad8P6Lg+4x5Ej91SMmCUp8CoEc6VbjNjgp5/xgvsjWk79WFbJr2L6X6qLnz
         33kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687278782; x=1689870782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AKf61092/rwaAg1su3PjYbmIsldHEjPTlf5Y8SGawzA=;
        b=CYDJd3dnAYkvS8CtXr3YPH3EOpIOCjsty3TEgGIaEXADSo3OWpoYRrYIe+xRX9beRr
         ziNKf1qa5DuczLx/Bs+zosEiHpLE7KSTIY5R5YQhm0YujD92TxRzmuZGpyjGMjcS4kDg
         U05kG/BAxGDRr0JUSq35/4D0qEqoa6G6S88RXC9iZ0kuY8Cu5LRGOTIbF7BmyGgmsDiN
         Q+omh8jjSmzs+IQRF8WoWkNM4A0pyG73tyEiT5PwyoYjYshT2q38uVOpxPSbJYKRt6Yq
         8kWs/XWm2HflIqcBIUrOL+HZ3oi2WXeffEk40FSgAiqq31o48qxoN8tr9Ov/rR4Fo14p
         Potw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwmvfxNVL7A3/aSybpGaLilphd+C2B0R/Jlv3E5q4whk8km/oHD
	LqiUAxhh/bSzJW2UKHc3c7Q=
X-Google-Smtp-Source: ACHHUZ5rlupo/0oa9p2B7b7jws3byG/xg1TOiXkAoG2hvCnPUzU9V+ymnsrF+dE0OdpTS92O56uI2w==
X-Received: by 2002:a92:4b02:0:b0:33d:ab70:3447 with SMTP id m2-20020a924b02000000b0033dab703447mr12218082ilg.19.1687278781992;
        Tue, 20 Jun 2023 09:33:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e4e:b0:343:c171:fd9c with SMTP id
 l14-20020a056e020e4e00b00343c171fd9cls237190ilk.2.-pod-prod-04-us; Tue, 20
 Jun 2023 09:33:01 -0700 (PDT)
X-Received: by 2002:a92:c10e:0:b0:340:b1af:bc1b with SMTP id p14-20020a92c10e000000b00340b1afbc1bmr11909571ile.23.1687278781374;
        Tue, 20 Jun 2023 09:33:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687278781; cv=none;
        d=google.com; s=arc-20160816;
        b=HGXSfHW+CeVMIBGxQ3Uzx7iUPscB+3mjG24vsQfw+87c0VlYkvZEmHIAQOTJccDr2c
         Zkr0auO4IBXSh1VRBzfTf4EoPmssETZKzNPVLYpARn7nNJvm+d3zikDMjLBbEOa9UqRK
         MKDb0ZJTy28Y3SseuyT3w6Iz1mOGzYNhU8AFBlwjwmSTqmdIHELRCEmLGqwDXfBgLck+
         KM3TPsP422cV5HVUivPMfWiBzHVG7OBe2YfHBDpPftySYZemJIaLSrk552h9yPdSyQvi
         3zqZrpMmvperdojMgklXgKFx8JfmxC/f2cODVUyYG4yo0NcKNtHMjkrGLsqwxBYVccvl
         Zgbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mLP18OTLuSxDA7X3Px473B0FeVYKNM0xRJJ/SFynJwI=;
        b=S7PY43/My9TRb6GohRFQwnz8GwNbI14HD4jAJMUkKnG6tG+lQi49R9uVKQZQsWqyIv
         K5XJOk7cb+JqpQWHcIqBucfnPARVQlyW8iZfhjDBfMKEZJQp2w4+e6BbiI6kzaopj8Tv
         IC1f4urpW+GcB5Bs13uN+0BBAH+s1yNhN+BAUetvUp1wcDhNtEf7dCDMF5HYGW2foLnA
         aVQ7HQLeMUTbooFcqEWramK84axizPoH8QSLyQ/eB4ma0ZzOHTChXv+VbPSo5KyUN18Z
         kXJMdCENzVhS65kwsUiBYw+6GCGkJztZilm1wr8fTdj4edkjBL7ypNozIY0mB6xRrCMY
         vVyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=o31p5LIv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc36.google.com (mail-oo1-xc36.google.com. [2607:f8b0:4864:20::c36])
        by gmr-mx.google.com with ESMTPS id v9-20020a922e09000000b0034201149242si160696ile.4.2023.06.20.09.33.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 09:33:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c36 as permitted sender) client-ip=2607:f8b0:4864:20::c36;
Received: by mail-oo1-xc36.google.com with SMTP id 006d021491bc7-55e40fac2faso1805278eaf.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 09:33:01 -0700 (PDT)
X-Received: by 2002:a05:6808:1b06:b0:39e:dbb3:5528 with SMTP id
 bx6-20020a0568081b0600b0039edbb35528mr7280934oib.47.1687278781003; Tue, 20
 Jun 2023 09:33:01 -0700 (PDT)
MIME-Version: 1.0
References: <20230619101224.22978-1-chanho.min@lge.com> <CACT4Y+Zn49-6R00buq-y_H0qs=4gBh6PBsJDFBptL8=h6GPQYA@mail.gmail.com>
 <CANpmjNMSfVeDa-YC-RQcZ-V=wvHGi43xvXSvaR0GQkEP0OOmOQ@mail.gmail.com>
In-Reply-To: <CANpmjNMSfVeDa-YC-RQcZ-V=wvHGi43xvXSvaR0GQkEP0OOmOQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Jun 2023 18:32:50 +0200
Message-ID: <CA+fCnZfi_o6QbfDamUjsPXjtnEwKyBn8y+T8=zxV2mEpA=DUyQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix mention for KASAN_HW_TAGS
To: Marco Elver <elver@google.com>, Chanho Min <chanho.min@lge.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	gunho.lee@lge.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=o31p5LIv;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c36
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

On Mon, Jun 19, 2023 at 1:36=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Mon, 19 Jun 2023 at 12:15, Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Mon, 19 Jun 2023 at 12:12, Chanho Min <chanho.min@lge.com> wrote:
> > >
> > > This patch removes description of the KASAN_HW_TAGS's memory consumpt=
ion.
> > > KASAN_HW_TAGS does not set 1/32nd shadow memory.
> >
> > The hardware still allocates/uses shadow in MTE.
> > Though, it may be 1/16-th, not sure.

1/32 is correct: 4 bits for every 16 bytes.

> I think the point is that it depends on the hardware implementation of
> MTE. There are a range of possibilities, but enabling KASAN_HW_TAGS
> doesn't consume any extra memory for tags itself if the hardware has
> to enable MTE and provision tag space via firmware to begin with.

Yeah, saying that HW_TAGS consumes memory is wrong.

But it might reasonable to spell out what happens with memory in the
config options description. Something like:

"Does not consume memory by itself but relies on the 1/32nd of
available memory being reserved by the firmware when MTE is enabled."

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfi_o6QbfDamUjsPXjtnEwKyBn8y%2BT8%3DzxV2mEpA%3DDUyQ%40mai=
l.gmail.com.
