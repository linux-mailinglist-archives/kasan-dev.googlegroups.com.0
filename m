Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBZHI2TXAKGQEKS2E2KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CD55103A33
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 13:41:09 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id l6sf16263503edc.18
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 04:41:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574253669; cv=pass;
        d=google.com; s=arc-20160816;
        b=wUWzQblCpr96xwxuanSPE0zXR3GQ68GrQk9YgCU9Mgip6RNcQhpnK0Mq/MIjzsRq52
         8fdEIHSIElDRz5AFTHE9IBXC8TUy0pSUBL0N146B4GtD3scLt9PdDtdM72TSu3x0qrNh
         uHCfVUk4VjnOtarOnTXvWZkcWmWelqX82Da0omaxj4lN/LfTS1hwW27jt7N518L3B34b
         cosjsecHs8Em9wYKCU89nTYwt9uqpjuniPVaON6luCqueY0QsCc8M0ot8erJRQEFxjNK
         qL4MXH9BIHfiNL49p82NWKJYKN6Q1qBStndAidvCoeDqViPwMy8ZojD2TiAa1cb4z1YW
         /0lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=39AfQ4deZav4g1wLoNAcpty3hQ8Wo4++wFqZpFXKjYs=;
        b=iVvhtca6KW1wYYkwsRt37z5M3/vl8mfYTUTsNPE1vQdWCwQr/+a9jpQPjVeV0ymmT7
         KpXnhZ+Q9ceKKBXgOMr4/A9FFFkil/KC66rOT5/lM1btd1Nb4zCNAGEi5kJZmxb6CWa8
         X5c7S/MIflLeDfDEelntcr0vWb+KveRZuDTCkU3V3R9JT19FSIRy64RlluU4dOtWh3qT
         qRmSvuQ81CvoH6YMcvwmn2VMJld7Q0HKKxaZGeB1ryF++RqzDJUqMXxe7Xub9LewRd/k
         jxszE/1g/IELEvpxW/9l97FnL7Ly05haG1Xqjps7Qi2ORWyVfMmqxpkBU6ZaWlZ7boiB
         MAFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b="c/701oUR";
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=39AfQ4deZav4g1wLoNAcpty3hQ8Wo4++wFqZpFXKjYs=;
        b=lTJ9VBjRGiDGbE//fehvg14R3V3KHge8waDeV0c435tCMmYA8lR2v9io0BoIzWiPjb
         WeOZ8X1XGdA4GPMU+m+5CIe84O932EWP73zmO0EuURwGTrIfVjN1PAP8snfIrwpqvl6b
         ikRS6NmlPIXtdqlsaLv/m50V+XVYY2ZHU6rWMuxXCoWGyC81PGTrCId1Hy2uqRiVSpO5
         5052VGmCFVEQzY2nY4jJ/avn+Qoj44KnfcxKOd6hKyWC9oiECnCbSqysMKqnEK5FLMok
         TdpDQq7ILrWwzV6ZTFWK7DKR5gNB0UOjpdYqXkH6IqTVXQMZp4gRdZoOSv8ISsBvT/t1
         +j4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=39AfQ4deZav4g1wLoNAcpty3hQ8Wo4++wFqZpFXKjYs=;
        b=GmUi5+dy+iEn+wLAchFzcvSri3FBycFyGi0BMX+U82ibMXiIFYP94WQMZpnohf2yKP
         p8oTG8Tc49YCj287GTwa2AZ6kRtZiF2lwzGa3oGstl69o5acoCvWX+5cKzYFAqCYg1ai
         UkqMtS/DFglNvPizwEtVz00YJW2Lp1AC+CLO0/AZbBZ1dmhW32QPbkKIcxGzV377RQLq
         0DDZAYCwcQwPDFCMQfV7ulnx9zUrhLgsCSPHOfKoNOzsCoGN3DDvaqevw6LApbpaIb+X
         nFfsoJepPjdpaMgo8gQpYGxIwYzk+wexlBdtGbt1gSOlD5LPRrjah1WypS3TzW8+4ojh
         o+2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV0BoLmuFmsBFjm1imvPrQWMlrwVRaf5iNDaFv64Bu6zr6D/Miv
	PdTESgOJPmMXFbvS5ECeNzM=
X-Google-Smtp-Source: APXvYqw/krgptnkm5QZfD5Fs4CD1PIquF+EHx3FvOnV/DMiGV3WbZD+/L58RLkpf2+dhHEFu5I+WaQ==
X-Received: by 2002:a17:906:57d7:: with SMTP id u23mr5354189ejr.130.1574253669019;
        Wed, 20 Nov 2019 04:41:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b857:: with SMTP id ga23ls1005939ejb.6.gmail; Wed,
 20 Nov 2019 04:41:08 -0800 (PST)
X-Received: by 2002:a17:907:1102:: with SMTP id qu2mr5182933ejb.300.1574253668578;
        Wed, 20 Nov 2019 04:41:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574253668; cv=none;
        d=google.com; s=arc-20160816;
        b=NnyJhFK3lUAH6ID+d3Ug9QR0Q8nDqw6xI314SHlYpjoR8Jhu6Fwj0pTYUObQxSF3Kb
         7aF3E0Xjb1LLAhE7O+zZuK8dOYV5ijRee/ILwSu16qKMe8p/dglWW48vMb8gvWgq3JKu
         tlOksiikR1CGPNRIixRDPq4skqAvh6LVtKWV/gX37jg5TzF5NyHuY+BZBB3L15fQ4dV8
         7rX+kDSSFjddMI+T7sWjNnuQI8/9AcHTSSLVXx+DrMzVUoUr51TSTm5Ib14AZ5I/pD1k
         6IDraMcAfM8eTGyDMOe6kaAbc7RCVb0hfnrIkpaX0CymWtB4QV3L4gu64Ac7Rio4ZGl0
         /DYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ea8pQqJ+Jjuj9IYCptOm3Z7PI1Mh+ByTGxj7asJ2NU4=;
        b=XS0c6gbjR+8kGznA3sfQAp/dbdkCH9jdKXpBT+zukdeJyueu2wyrpJsgwRojChZbDy
         OfCusWBQE3/UezZRBJRB3kdx339dTgACbfClxFCU7tmjTCaTfswr20VtdVBeJXrkduKJ
         4d4p5tfdVuHLPQYp4/LwVTB+5JW5dDdNimQbl4djxw0aV7gj4qQUml4xdAKlFz+LkuYV
         2Roxif1cmSWOGaIOuwuPZ5rYB1rurtG4UxHxJfkYVYWEbjLn98VY1mVpZMLImlQULQwY
         uiGlZNbsTI8u8cg80qQ6xMXH4F0C69+wxRYQRo6dzIx9VBBDNQKDRX4DJ2WttqH9c8VZ
         hpog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b="c/701oUR";
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id l37si1242577edc.2.2019.11.20.04.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 04:41:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F0D8C00B1B17C12861BCCA4.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:8c00:b1b1:7c12:861b:cca4])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 0889D1EC0CE2;
	Wed, 20 Nov 2019 13:41:04 +0100 (CET)
Date: Wed, 20 Nov 2019 13:41:01 +0100
From: Borislav Petkov <bp@alien8.de>
To: Jann Horn <jannh@google.com>
Cc: Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120124101.GF2634@zn.tnic>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <20191120112408.GC2634@zn.tnic>
 <CAG48ez26RGztX7O9Ej5rbz2in0KBAEnj1ic5C-8ie7=hzc+d=w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez26RGztX7O9Ej5rbz2in0KBAEnj1ic5C-8ie7=hzc+d=w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b="c/701oUR";       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Wed, Nov 20, 2019 at 01:25:30PM +0100, Jann Horn wrote:
> On Wed, Nov 20, 2019 at 12:24 PM Borislav Petkov <bp@alien8.de> wrote:
> > On Wed, Nov 20, 2019 at 12:18:59PM +0100, Ingo Molnar wrote:
> > > How was this maximum string length of '90' derived? In what way will
> > > that have to change if someone changes the message?
> >
> > That was me counting the string length in a dirty patch in a previous
> > thread. We probably should say why we decided for a certain length and
> > maybe have a define for it.
> 
> Do you think something like this would be better?
> 
> char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;

Yap, and the 50 is a sufficiently large number so that all possible
string combinations in this case can fit in the resulting string array.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120124101.GF2634%40zn.tnic.
