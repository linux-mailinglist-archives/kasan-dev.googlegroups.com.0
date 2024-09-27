Return-Path: <kasan-dev+bncBDAOJ6534YNBBMUZ3O3QMGQEZSFVN7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D5AB988811
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2024 17:18:12 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-37cccd94a69sf1098684f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2024 08:18:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727450292; cv=pass;
        d=google.com; s=arc-20240605;
        b=EJ035jIptjg2TKsNpCChrwMm/3+GypV5fBKckM41FegLSYiF4Uinlx3sO7VfPl2QwS
         UQaw7n7NXL7jhS62nXAqlBTVFnJ61cw8hU9vGxyvZO510q0L+h1tF1ZBYJ2+hD7XwmR2
         9gdkJfREjOQXAj80VTMoa40odck8fBDxGdwjtWRQ+U3eD7vUG1kQZTORx6NxHxaH1gZS
         nOnvF3QkIppcB/enatLGc9f1PkMTz9hQNL0pK84ZKDSywpSf7LZsOpdAinpzjzywVKzG
         yzT00/QZ/MVhhSHMI9We3cZq6HMq0iszEjxsjN7tP7Mdb6M3Y2+ZtWCkBGUS5r4pNCD9
         Ihfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Jz8YzAb71AB+Dt+OEt7GgCpYS8zeGBUIPTfI3Aywabw=;
        fh=9IzHN8GwougZMSulYopUByn6FotYAMa4KW5QuyQfxyA=;
        b=Lxweuo6fA0JZ3ltBGNP8F2k5vawpYpIghWE/Qvm1yspoTVqhI6rJCzkeUeiiuyaR+F
         yzrpaRl95+cfD/YeTDK0OMl/FNZ1/2Y2RFeldoQxTCX2LvghYlmeCFwy9EdOqm1/Cq+1
         Q5nTSWPTqyu1VxbneUpCDKqHpzXhdXEpfdOqId/mKBshUwDG3s4g9YYj2CcjzFs2xjkV
         pbt4Oe5ewDV+JC+LRs53ig/lfq6pwpcSc+DcQF5QwnVy7EeNgYa06lkrn1w+LcpGR93q
         1EV/zRQA/M5/rPMH2My/aylo3j+rtcd8FS9Cz/paOXhw9KtYYO8+X5R42VVrjspLTL7h
         xU9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dlAjs5f/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727450292; x=1728055092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Jz8YzAb71AB+Dt+OEt7GgCpYS8zeGBUIPTfI3Aywabw=;
        b=Ex0W/n3xL+F90ex5t61Ns5a3pwUnDku0tv71stJUCEdzUpuRoNz8ZRZAAgIM4U5Hzb
         U8P8aTU9CZm1gPWHYdWmeG0XDcoLAsaHBbds+MU9ZvBfn8QlgeP046/rJhfQbO5cftpf
         Wiahpc6DerGWQEhHTyCpMTYSvkEgs7q9z+V81m0ES1P9IF2Fl81dZluRaS15NWg3s7w0
         YT3Wd1DDntmrmX4ggC0ALpCp8e6UxxusYJ1gJ7/VIQYEiaiHaDhfnLL5lJh3IWvcAZKU
         cY3842871j4CwQHrN9VdxfY9wmKQ7/kt+CyK6U9nBpDFXSbMFi0tvTAFzKphbix7JdaD
         M0yQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727450292; x=1728055092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Jz8YzAb71AB+Dt+OEt7GgCpYS8zeGBUIPTfI3Aywabw=;
        b=TE1L5Jdtk9Fh2dyNReIu8MoAgTUwAv6Xofr/eKSpkW05KZqJmraUROMKe+NApnVk8v
         XuREi0bZv21uXDma8eM5WdD63NYk/zJg83B+3evvBqw+HQrUq+2+CCKMXL16rBr3TSjC
         /TnEnTg0htaXuiWg2fXbNdGxgSzlCw/FvG4BCRwsGo3IhBAlCexmvni84Ltt/HKr9hKj
         7fkLArA+3g9E9Txy/XaMigX3D7QodtnRaDzh2O1xLYRxwD5B95rIMCmbPpRgIcatZmH6
         OTXNLkGt7oTqMOvw84zjk2Vu0U2BRTK/KPPjayZ4Gi1EwZjojN0v7qugbZ+ANMDq0b1Y
         rYbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727450292; x=1728055092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Jz8YzAb71AB+Dt+OEt7GgCpYS8zeGBUIPTfI3Aywabw=;
        b=OUwWMi84Zm5ec+ckE75EoeivE6kcvpAfq1wyw3GIgNX+rvhqdY7jqPZwX5jgj1jXLu
         jF3pxlnlEibwi4rH9z9x0OroyWDseSwM7XsPOsvymTw4hBGuA08w6acnk2cxIJ+q7QsL
         d2LPUdKXC3pfNJPSawd9Ehkvna6z1g44e3eko01qUmBzilE2gOo2KXDAuOhTW8iED+VA
         F5kUKyd9PuEqYuU5FObp23K35ivfWFZodeK6q8Fs/ex/A1oNHx2cogA6KdgErCRlUdbH
         PtmV8dB9jkhYJv9xkm/iUpznDv4SQ909ZWlS9+RcahdIsBPK1QVf+b0/ZJtkUQgNQC3u
         blOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVezQOLYYjP4let0iJDW5v4JGYIWxalK7XyL+5K01xpxAXQK2O/2w4sLCxSY2Wwcp8a8LFFnA==@lfdr.de
X-Gm-Message-State: AOJu0Yxpst5SrnUOFNVtQbpqlNdLrd4/OTvUwDlDF9PhmJgzWecVtQa9
	0XTaVAdHpEby9HLfZFU+u2XfRRf9SmsJzarsmjAKUgzGSMfMOZ0I
X-Google-Smtp-Source: AGHT+IF+P4z8CSUogHmEp3c/NLGEJYIxMIO4EfCqmYO9PT4T3w2WFB/w/7517A/5Ybds697EGQuD1g==
X-Received: by 2002:adf:ab47:0:b0:37c:d28f:bbb0 with SMTP id ffacd0b85a97d-37cd5a9ed7bmr2676359f8f.20.1727450290950;
        Fri, 27 Sep 2024 08:18:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f85:b0:42c:b1b4:db22 with SMTP id
 5b1f17b1804b1-42f52234f5els1137315e9.2.-pod-prod-02-eu; Fri, 27 Sep 2024
 08:18:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWv2npUkrcS7hzvPZqGzfuf3APTox5UhVBTO+MuviOu1pV4JPyegbp05bdjcmgu8uoE5C/TMr0KYQQ=@googlegroups.com
X-Received: by 2002:a05:600c:3c92:b0:42c:ba1f:543e with SMTP id 5b1f17b1804b1-42f58497f54mr25401615e9.26.1727450289148;
        Fri, 27 Sep 2024 08:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727450289; cv=none;
        d=google.com; s=arc-20240605;
        b=XLvZInqV5fTVm4J+cR9NSSP7nZh6WNVpAHpCXKFTTmXg/76jZ9x9gOTucPGg3IdbpQ
         xtMg9UO8itXysx3+JZoYDzlkRSA3H2NrwgupGTBA3IDMKBtdzF5A8GzSd8uTHB8jor5/
         E2LDHBfg8qovsdViq39z+OeZiZGUhqMSqJhWiAepEkojBrzAs+uNQIeVro5dwBrZT72E
         FO74+xeKzdRerwvFoe82jdVoQEAzsg/9mGpF9KcLOpFT90TewfFpMfV9dea5XE9Y1nj7
         mxEUem2LBr2KR5+iZDqxZb9Xy8+Y2rwp1nfw9tvou21eVa1N7b/se/CjXQTqRb7zXhQK
         s0vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3SScFSnuQe1/FEIIg37+hL2l/VXFwiSz3zKaA3JRboI=;
        fh=F2jMUbh1cScOqklV9ZIZNm4EHOElJpW0csDizTbzg4A=;
        b=dwIQqP0TIt2IuIkDuubkgrkutxnCSHKgFjrwHlcos4iDlPFn1cv/RNClYr6HzVyAqd
         2lK66dAua9FYlyKRQC6lX2GlqPZS5iDxsy3VzDWuzCbvkJjm1Db+sKvTHqUgiqXiaX3T
         bjVA5YVweEC+dQPFYqdGWgNcXE4e8A/PBflcDwYEnR3wEzT03u9zh1qEDuob2VXzn42G
         FR25Czh+EA/QWc1VsPxh6DQAlFCdnvZG9BcoPw9p8bAJzTf9TbgzHi+oJyEv3sfrIFE1
         Lh3b/0+mU/ZVMExl39xMwV1nkqNIYN9MZqq1EeaOvzSS8nVmy4OvfQ3R2p933fudKTOx
         V/LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dlAjs5f/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e96a3c27asi1410605e9.2.2024.09.27.08.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Sep 2024 08:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-5c876ed9c93so2262029a12.2
        for <kasan-dev@googlegroups.com>; Fri, 27 Sep 2024 08:18:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnUPUxKsO4JMyv0OdD/pkFhQHL5TXks0xSsIHe0+au11odjPJy3aOCSQ13Mms7cBkVhafeSBUWTg4=@googlegroups.com
X-Received: by 2002:a05:6402:35c6:b0:5c5:c4b1:883c with SMTP id
 4fb4d7f45d1cf-5c8824ef708mr2520367a12.4.1727450288449; Fri, 27 Sep 2024
 08:18:08 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZfaZGowWPE8kMeTY60n7BCFT2q4+Z2EJ92YB_+7+OUo7Q@mail.gmail.com>
 <20240922145757.986887-1-snovitoll@gmail.com> <CACzwLxg7_HPxbjLT1v+dHG=V0wAcUJYZvqdcdLBD9xhLgNUmqQ@mail.gmail.com>
In-Reply-To: <CACzwLxg7_HPxbjLT1v+dHG=V0wAcUJYZvqdcdLBD9xhLgNUmqQ@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Fri, 27 Sep 2024 20:18:46 +0500
Message-ID: <CACzwLxjpH=n5RDWnQCPZjH8i1GZAAbG-6BzuWCcVf99=qTO7HQ@mail.gmail.com>
Subject: Re: [PATCH v5] mm: x86: instrument __get/__put_kernel_nofault
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org, bp@alien8.de, brauner@kernel.org, 
	dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com, 
	glider@google.com, hpa@zytor.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mingo@redhat.com, 
	ryabinin.a.a@gmail.com, tglx@linutronix.de, vincenzo.frascino@arm.com, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="dlAjs5f/";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::52e
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Mon, Sep 23, 2024 at 11:09=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> Instead of adding KASAN, KCSAN checks per arch macro,
> here is the alternative, generic way with a wrapper.
> I've tested it on x86_64 only, going to test on arm64
> with KASAN_SW_TAGS, KASAN_HW_TAGS if I can do it in qemu,
> and form a new patch for all arch
> and this PATCH v5 for x86 only can be abandoned.
>
> Please let me know if this wrapper is good enough,
> I will see in kasan_test.c how I should use SW/HW_TAG, probably,
> they should be a separate test with
> KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_SW_TAGS);
> ---

Hello,

I've sent a different patch [1] to support all arch checks,
tested on x86_64 and arm64 with SW/HW_TAGS.

This [PATCH v5] for the x86 only can be ignored.

[1] https://lore.kernel.org/linux-mm/20240927151438.2143936-1-snovitoll@gma=
il.com/T/#u

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxjpH%3Dn5RDWnQCPZjH8i1GZAAbG-6BzuWCcVf99%3DqTO7HQ%40mail.gm=
ail.com.
