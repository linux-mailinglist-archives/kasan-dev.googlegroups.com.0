Return-Path: <kasan-dev+bncBCSL7B6LWYHBBMUGXHFQMGQEK3JXCVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 20BADD3AC8D
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 15:44:04 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-59b6dfc0cbasf2727930e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 06:44:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768833843; cv=pass;
        d=google.com; s=arc-20240605;
        b=H46sUYB8GL714rEDrK7a77JwlhmS+DuKidhxTXVrtQYbzu3j2EaX9e8DpF1gCsgaWB
         KjRUKnk59tU4dqwh4W3zRqrUataXm4r+BBZKnB+vxE5R9fqEh4Le+F7JVZG7NlaswMvw
         wnoVCvkzXk1qiKYVpArQT1HziiffSMp4LwBE4U0ELQSxjmtnDauI61oFM7w3WUCHHPh9
         yPPBxWfNn5ALMmIFIbR1Xd64EGhB9fsuOFC9NYTS4oFejqAfDf8Kwr7n45XmX26kDAg9
         rTmQmrzrS4kJ/LZkriSwRpcB6jZWrdmENo5lPsZCg8FmwdZd75wTrHOiVAu2excOv8KW
         xlbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=HuD5X0lL6zpJWq2OCndohSwYVHG+Ep0chPq2aGTUYCc=;
        fh=TeEud+8tQeX1sSG47DKELNqWEEXTO5/Z8ahm8OAxkoA=;
        b=MPVvH2/3fnB9XHM49PfLyQ0JkMWnWXgw62YTCUmxLelNpUwMY8UeL6pOlqyovD7Hl7
         hgegQaZMswe8cIY/ewXfJC0HdMCROkxtF5DnGkrFnz+N3QUmAsmyYf00JTP8EpMSJITv
         B7Id6cRGBoz9eIwpvLNqOy2QQl7+8SxfH0B912qE7d9NiuCuY48Nvcd+Z6JdZEhNVDtb
         5BmZqYBxTje91scooRmbDLZzWMS8BGYA0IFm9sM3wsBR7HBJnHXg3miLIWVWNEtD1IOQ
         ZeVfYFbbTzSTnqc4HLPQyY0FJXFdH3ten2526XRUWkXDcLlO2jzVO6RhQ1/oBxSK6pYu
         culw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Uz1dUzs9;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768833843; x=1769438643; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HuD5X0lL6zpJWq2OCndohSwYVHG+Ep0chPq2aGTUYCc=;
        b=Y+gJP7p/QqEaXKxIcBOq3vzAyJehqtDGbusGTd+yqOdRU8k7cvwUFcw+zgmC6Vmb4M
         fKslvnOGmu7UJ9IMkvMEOvohXKdtfoFegTjmnJrpZswzr9X3o7SbEKP9M6OOecfa/wcS
         uDI2QAbw+ar8oEYkusa7SXD7VUD6vqCSBtfyy3IZRsRA21e4/heIRf3nM8Q78S6J9yD/
         v7VigflZ1jrjUQNY4iReyVV6KLgWSXk0PkwPWLRkv4nJwusjlArhm5WBuQvsbnJNvUnv
         Uwl79V1FZCJ2GJyfh0NhNk0+rfi0mEqTKhfz0jFYKt2s2TIuz1z1J7kZ0ioputnCJ7MC
         K0Fw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768833843; x=1769438643; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=HuD5X0lL6zpJWq2OCndohSwYVHG+Ep0chPq2aGTUYCc=;
        b=Eon3/o0S4FTTNlOXifxNftRnyFhO22I42xgLiyxGi03r3Hv88ISJdYrjjPSuzavD8D
         hfQ19sIQrpNUo/A1gda2t2r6edyVZkwzJsv/jcsybq8fiiqo5LgEs66C4OfHLcq1LigC
         /ThBprnfIEMR9kRgc8dUqU4j9BIqI1yYDNKK413KrS/TKkvIyU/OzHgGYFl/A20tCbt1
         bxxDp2Q3YuhU7hi0U/ZuX6wlzRw0Eyz6auWpPhZmzm/NrY3UM8+Xj1gxJsJ9DgCBjiT0
         ZJU+uO431i93gFPwuPW/ZNdRk7KhYq83+YjnloG92GGzb3mHnq7wpP7fyGdI0PmHsJK/
         vrSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768833843; x=1769438643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=HuD5X0lL6zpJWq2OCndohSwYVHG+Ep0chPq2aGTUYCc=;
        b=nxw7SN2OaeRmdGnWORVf8AMnt7PCwcC6O7SW4cV5di3J8oHDUZRQhtK4LmUrITWT05
         043nDWiiU/51RGTANEZuHoO6VHUWkFIu8UsedkiGq2Mv6UP4VBL0PtPohCMI1HpbIl6e
         bo4Q5rvEpuZyaqxfjLSeJowr1cBPdiA5A7ncFHmobivwQP42w4gDwJYHqq+W00NGH4/2
         cNe4QUHm680az+A5/oLD590QPsT8q292GCBqW3QxkoaogTaMJnorT1rIqp2mX1SZBJCj
         k6t4pc3/fhno+4DOQrjxkm2hzBWiM3CpLYBDtMbsalhQj+5ssuXD3hL3pGfm89/INnaw
         k6dQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVYLwFS/EaixNsBgrcavbEGt9jGCdyhdKIi5yRDD0HP51Cv8vYvEbr8BvE6wpPUcEB1ZShKvA==@lfdr.de
X-Gm-Message-State: AOJu0Yw7cJHzoEie0WKbMBEYGsYysd0oHA7sAydpgOk30cxEQKZ8JFVc
	GJAX9VToWtMW8fjmfecRBPDk6Q07OCgelUNkvabuRm1fjJK611YeDBfX
X-Received: by 2002:a05:6512:10ca:b0:59b:7da6:24cb with SMTP id 2adb3069b0e04-59baffc59a7mr3432289e87.28.1768833843068;
        Mon, 19 Jan 2026 06:44:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FT/Koi1WAwmhJIN0H8Z0QuMSI+pkPC4DHV+lpAAdmWTA=="
Received: by 2002:a05:6512:b26:b0:59b:6d6d:e with SMTP id 2adb3069b0e04-59badf258f0ls1861195e87.2.-pod-prod-04-eu;
 Mon, 19 Jan 2026 06:44:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCXTjKfAc71Dn2gXlLsrR2jAcRDmnymCC5nbDC/2QSa4Wxh1Hsjtj4H8LBzPRvlShBe8KQnPIC8+w=@googlegroups.com
X-Received: by 2002:a05:6512:4010:b0:59b:b41f:72b8 with SMTP id 2adb3069b0e04-59bb41f72f9mr3611893e87.31.1768833839973;
        Mon, 19 Jan 2026 06:43:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768833839; cv=none;
        d=google.com; s=arc-20240605;
        b=UYvKZl2Wdur0N0fAHNQQViZp08LkJtHBfGVoC1VdIDoRKM6PBnKBYDEEARv7hbJMq8
         2Y5aawQ4TbABsyuyOpCNBs1CEab+twHci6Eop8S0VFR2i5XZ3NCx0Pd4lgVqOuvVUwuT
         CRG5JT5JWnVlPPsYNOT7Rg+JNs9P0sUUWSv/GwvwRuYGpizvmu0xA+kgcOX/HoAr7Zyr
         fLEdbi0wLI2tNymI+nre5ZgRQvRAxjrxhjFy4uQBwfSKKpIcmnanle6dH4nJNvSDuHGN
         o7UzQJQ+AAcxq2zIgTSWjfx9zAW1+pqKohomrHl9oelFr4h/YHdwECBGviAKbOAHPHEL
         gHEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Hw8g4FncQCT0qG+FJkoHCdORpG7mMrMlB+H9ZegPebQ=;
        fh=yNNwUxdZxWCH8zsVEWr+Gf+TF3X36E4B+kPoa0zgKDY=;
        b=JELky3sSFDX/Zx8pl1W1YKnXjFAnAifoaKZ1XTkH1/b7voPtvD+9CpJ6zTQMt2cTIN
         zjhjTojQ0tsp4ZmcShETZ8HCyTFzrQNWFTlmQ1/P+FJBFtAS4ewoIzuGzGuy8+mDn/sR
         1wTgq59aRV87p/DnpWH/Dc/AttjB3Ot+6fnAl8Q/TgWYUO1T0qBXSU6D8acj/Z8F2SKr
         Kh5seX/zcSGDVXAgFBhF7r85Fk6Z7LXJ8LcRbqnH9N+9DHyoNZvUDg4+4Kt21pvGuVxi
         yuwclHIIDeUkA/yNgMteSrF8NcsSzlOSnEVqpJUegmEdseZuobSieTxdDmmx+bpx78Cb
         VNFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Uz1dUzs9;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf393418si176299e87.5.2026.01.19.06.43.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 06:43:59 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id 2adb3069b0e04-59b9fee27ccso454499e87.2
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 06:43:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/wBDX7Ee/aI375ueALIhEpSTwZljixqbtYmDpX46+LOBU7OVKwlL+h2bEQ59eXjiou9FIZozpVPI=@googlegroups.com
X-Gm-Gg: AY/fxX58QT5uuoQRrbjGTKcKVWNHvE0W/jZe/f6jPjvXBu4tCFkFSAUhPD5vvevPV3A
	hR/R3Lu9nkq5g8/JH06dtcaJxm5wb2rM79V6xJiNoSziLixYinYqhX1E7f0E9wMQXTNLDXD40MO
	zFCAFwhivExWY3Y9dciBkvkzt73C7Wg27BiUaEmrxNtu1FJLffmYhMpLnDaSczXDxJ0ODUZSdAj
	4crxNHdWh+HYUc/pXP0lrln2/qAWX0PpFTY26vUiLLdu0zGrGPfRbMPNs828dHW0h6AaG7yhy2N
	xvxXDlL67d5v6HlKBGWYWo9Z+KW9H64Qkx10MUsbAxKeHX5qujQLVqD5AQiaIvboK8uU/XpnAmB
	3QOV91JHsFnDK+3BhuIFJuTgPc/RO3CwuX7uejT3hnwugXFUz4UQ1tTZE99sA1S5Pj/+Ye5kbD2
	aK6qgFM9sae9zLepm7uGv1jfSMUMhh
X-Received: by 2002:ac2:4f14:0:b0:597:d7a1:aa9c with SMTP id 2adb3069b0e04-59baeefe804mr2049768e87.3.1768833839215;
        Mon, 19 Jan 2026 06:43:59 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf3a1746sm3435146e87.91.2026.01.19.06.43.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 06:43:58 -0800 (PST)
Message-ID: <38bcbe9c-5bc6-4bfa-b4ed-e187e048d600@gmail.com>
Date: Mon, 19 Jan 2026 15:43:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 1/2] mm/kasan: Fix KASAN poisoning in vrealloc()
To: Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@gmail.com>
Cc: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>,
 Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, joonki.min@samsung-slsi.corp-partner.google.com,
 stable@vger.kernel.org
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <20260113191516.31015-1-ryabinin.a.a@gmail.com>
 <CA+fCnZe0RQOv8gppvs7PoH2r4QazWs+PJTpw+S-Krj6cx22qbA@mail.gmail.com>
 <10812bb1-58c3-45c9-bae4-428ce2d8effd@gmail.com>
 <CA+fCnZeDaNG+hXq1kP2uEX1V4ZY=PNg_M8Ljfwoi9i+4qGSm6A@mail.gmail.com>
 <CA+fCnZcFcpbME+a34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA@mail.gmail.com>
 <20260118164812.411f8f4f76e3a8aeec5d4704@linux-foundation.org>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20260118164812.411f8f4f76e3a8aeec5d4704@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Uz1dUzs9;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 1/19/26 1:48 AM, Andrew Morton wrote:
> On Sat, 17 Jan 2026 18:08:36 +0100 Andrey Konovalov <andreyknvl@gmail.com=
> wrote:
>=20
>> On Sat, Jan 17, 2026 at 2:16=E2=80=AFAM Andrey Konovalov <andreyknvl@gma=
il.com> wrote:
>>>
>>> On Fri, Jan 16, 2026 at 2:26=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@g=
mail.com> wrote:
>>>>
>>>> So something like bellow I guess.
>>>
>>> Yeah, looks good.
>>>
>>>> I think this would actually have the opposite effect and make the code=
 harder to follow.
>>>> Introducing an extra wrapper adds another layer of indirection and mor=
e boilerplate, which
>>>> makes the control flow less obvious and the code harder to navigate an=
d grep.
>>>>
>>>> And what's the benefit here? I don't clearly see it.
>>>
>>> One functional benefit is when HW_TAGS mode enabled in .config but
>>> disabled via command-line, we avoid a function call into KASAN
>>> runtime.
>>
>> Ah, and I just realized than kasan_vrealloc should go into common.c -
>> we also need it for HW_TAGS.
>=20
> I think I'll send this cc:stable bugfix upstream as-is.
>=20

Please, include follow-up fix before sending. We have to move kasan_vreallo=
c()
to common.c as shadow.c is not compiled for CONFIG_KASAN_HW_TAGS=3Dy.
So without the fixup, CONFIG_KASAN_HW_TAGS=3Dy will become broken.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
8bcbe9c-5bc6-4bfa-b4ed-e187e048d600%40gmail.com.
