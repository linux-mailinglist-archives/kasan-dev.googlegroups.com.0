Return-Path: <kasan-dev+bncBCHOBQFLQQHBBCEOY7AQMGQERO2SFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D38FDAC2FD7
	for <lists+kasan-dev@lfdr.de>; Sat, 24 May 2025 15:18:01 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-403290c1620sf889344b6e.0
        for <lists+kasan-dev@lfdr.de>; Sat, 24 May 2025 06:18:01 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748092680; x=1748697480; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=1J8rS6854B4AO/JZdaEbZovZwDKfOkAnkMtz4WWrC6U=;
        b=xQ77Gm1J8/o4hRmeKccThRA8T6p1c0xIn7iet6nPtoazUX4r2qMntn/WYpPJS7iRbK
         cqkSXE0RDdrNeNZTZ0EcplO+C6OoBg/riWD2Pta8od4d8+GiW8q8770NtBfahOMYsnW2
         e+KcoB4i9r+suY01pLIYhohDRcb9Be0e60FqK3LXJfjRnLOS12pck7B9c7FnzViBac8k
         PxMORt/2BNiKrP22YatixKgLX1yxyCBpGJB64/0WfjsPHLFGcfttGYM5jCWzfGLpuY92
         D+rQKfM4pb7k4qEeUWp8+st03FExu26II2/S0837XmEtnj87njOK05CwjUVkMaB+uUq3
         vNfg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1748092680; x=1748697480; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1J8rS6854B4AO/JZdaEbZovZwDKfOkAnkMtz4WWrC6U=;
        b=g1jV593M2TM92Lvv8R8H86BW6zLzUZPcKvhZh9B1fgB9/xpbrchPySw+cmjUrK3uCB
         9Lf5D7QnMlqLMENNkcyTB7GM/pvLzamVa9nnoDIiAKB4fEYt/tHI2z3Ykxpg1i04FOvR
         O+XjCCuoFlnjpqaajzp1vtpFnop6BRR44QfwbCY+wWWBvSWVy0Hnb31CH8wKi8HhV+E/
         anwr3QvJoSV9I4PL1sAD5aCRqjUBbnLCEKGy8z3ekdBkQsoga0s2O4n8QjPnrC/Lo8/U
         QGDzytEH5jX6ysLb69sfeVedUpcIbY7n4HcCXvfJuDjz5LPFTNlI48E4aaqNGk3U/CWM
         PQow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748092680; x=1748697480;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=1J8rS6854B4AO/JZdaEbZovZwDKfOkAnkMtz4WWrC6U=;
        b=lSIgEsDI+FInXdClUAutFfOR9FG0nhXeonfUxm4/5UEF6cRO8lr+USlgwmZHtzBM2G
         VxSB5AsTSP+T3XuSiQObVUP1Y461oj7Vg6XyXOdc+RTnbFvfuBsFjA2jtopu4PdBrUE7
         tPj0ZJwdinBagc3E3+Ah9DrdUwEzEJU2v+N4LfgRZyavbkUz40H9KTQmBEY9syGsqeO/
         wJu+ZB+bVzCajxf3e/dHADD8rjAvOqYQuL4W1RErp2NTe9zUYnXC/GYzn1jEX6WRh1VV
         QWNsgdIGqjROKAt1l7oqbyKK35Swp3Gma2CvB20kWcHoBQyyrDp6KyY0TRIgAmI4T1iC
         QoMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWME45LNodllkRXY3e3PAVtKopCdzYxRPhEowzsqGNeTl92s+d/BC9kuVbfZBNllFR/EFNG2g==@lfdr.de
X-Gm-Message-State: AOJu0Yw00+Gumxm7z8Amukd6aSQjjvUkeSHIHgRV+5pEkTDJ6XVFyadv
	pISX8RD9s5y1CTbQ0T6016xoHGK5cLuttF6EoIRl7T8HqLQd4pGRM5nj
X-Google-Smtp-Source: AGHT+IGlO9n0fIMunCiu+iQOFqKxi/Wb2sB5PPvwZvqe/oFbbUZX+NNnD1X/REfZu2hJrC/+q2mLnA==
X-Received: by 2002:a05:6808:6b97:b0:401:188e:caa2 with SMTP id 5614622812f47-40646872337mr1714961b6e.35.1748092680293;
        Sat, 24 May 2025 06:18:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGdQa4pkZkDvBbUuRqOxKHp22QRy4WRElKJ3683ieei4g==
Received: by 2002:a4a:d504:0:b0:604:8bd0:c016 with SMTP id 006d021491bc7-60b9f754834ls243104eaf.2.-pod-prod-01-us;
 Sat, 24 May 2025 06:17:59 -0700 (PDT)
X-Received: by 2002:a05:6808:6f8d:b0:3f4:af3:74a5 with SMTP id 5614622812f47-40646813e66mr1699417b6e.21.1748092679395;
        Sat, 24 May 2025 06:17:59 -0700 (PDT)
Date: Sat, 24 May 2025 06:17:58 -0700 (PDT)
From: Selah Acostadh <selahacostadh@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <0fa6b674-e591-4222-bafe-0316e7ff0893n@googlegroups.com>
In-Reply-To: <CAC1kPDM2pUEwFRiUZFHKq_7sYpjARkFczJnp_FRu+r9-xYdgKg@mail.gmail.com>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
 <20250429123504.GA13093@lst.de>
 <D9KW1QQR88EY.2TOSTVYZZH5KN@google.com>
 <20250501150229.GU4439@noisy.programming.kicks-ass.net>
 <D9KXE2YX8R2M.3L7Q6NVIXKPE9@google.com>
 <08163d8b-4056-4b84-82a1-3dd553ee6468@acm.org>
 <CAC1kPDM2pUEwFRiUZFHKq_7sYpjARkFczJnp_FRu+r9-xYdgKg@mail.gmail.com>
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce
 CONFIG_NO_AUTO_INLINE
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3826_771244816.1748092678842"
X-Original-Sender: selahacostadh@gmail.com
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

------=_Part_3826_771244816.1748092678842
Content-Type: multipart/alternative; 
	boundary="----=_Part_3827_1410260170.1748092678842"

------=_Part_3827_1410260170.1748092678842
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

https://www.google.com/aclk?sa=3Dl&ai=3DDChsSEwi6u4jpkryNAxWhfG8EHfz-KFoYAC=
ICCAEQABoCamY&ae=3D2&aspm=3D1&co=3D1&ase=3D5&gclid=3DCjwKCAjw3MXBBhAzEiwA0v=
LXQVZHo6AsoRNN_hHk10uqxB7Jo70fftBBjiOdV26wL-DI-XMY0c2pWhoC9-AQAvD_BwE&categ=
ory=3Dacrcp_v1_3&sig=3DAOD64_1ogmwu83ub131Tt8wScUkN-AiLyA&q&adurl&ved=3D2ah=
UKEwikyYHpkryNAxVJBdAFHef6Eu0Q0Qx6BAgIEAE

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
fa6b674-e591-4222-bafe-0316e7ff0893n%40googlegroups.com.

------=_Part_3827_1410260170.1748092678842
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

https://www.google.com/aclk?sa=3Dl&amp;ai=3DDChsSEwi6u4jpkryNAxWhfG8EHfz-KF=
oYACICCAEQABoCamY&amp;ae=3D2&amp;aspm=3D1&amp;co=3D1&amp;ase=3D5&amp;gclid=
=3DCjwKCAjw3MXBBhAzEiwA0vLXQVZHo6AsoRNN_hHk10uqxB7Jo70fftBBjiOdV26wL-DI-XMY=
0c2pWhoC9-AQAvD_BwE&amp;category=3Dacrcp_v1_3&amp;sig=3DAOD64_1ogmwu83ub131=
Tt8wScUkN-AiLyA&amp;q&amp;adurl&amp;ved=3D2ahUKEwikyYHpkryNAxVJBdAFHef6Eu0Q=
0Qx6BAgIEAE<br /><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/0fa6b674-e591-4222-bafe-0316e7ff0893n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/0fa6b674-e591-4222-bafe-0316e7ff0893n%40googlegroups.com</a>.<br />

------=_Part_3827_1410260170.1748092678842--

------=_Part_3826_771244816.1748092678842--
