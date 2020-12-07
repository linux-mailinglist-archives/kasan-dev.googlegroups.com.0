Return-Path: <kasan-dev+bncBCS4V27AVMBBB4VXW77AKGQEYFKMKWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 37E072D0B2D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 08:38:27 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id d2sf192318wrr.5
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 23:38:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607326707; cv=pass;
        d=google.com; s=arc-20160816;
        b=EGMJ/HagyPIBbPWV+G/CRO5sQKJikIE9bNMhL9EmRRxFNiLmH9stZx9oetS4a6lVhe
         X97Y+lO+HtOpBHQKif95LzoG2J9yOiabw90Vxz+VYIA931iAjtniik3O/vMBzrZPgItI
         g3Al2crn5oVYkhSnJxIFaLadeNrRhoJqSFCoNaCrlEz8eq8oqpH1722VLYXtx7/0GNuX
         vU8w73l5Zm/cq6p5ObjPVoDzq7IwB5ZSZbrAm2zx29WRD819SPUUrBS0qTwAscxmTYk/
         /WlUOn/1aWL8a2TgEM3x/digSZVCoytlzmPB5Yjh4oDx4crdpkUC9dTkAAZ54ec8jw/v
         LdbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:thread-index:thread-topic
         :content-transfer-encoding:mime-version:subject:references
         :in-reply-to:message-id:cc:to:from:date:sender:dkim-signature;
        bh=Fnu+0NdsTJePCJI+6WoC8cdHSsMRNpGnp+tYr6asV60=;
        b=E+n5KQxvrPP4OBe9j2K/QD9C8becmuMiclJPeit6+Xq73W0n9711lPGDq25Tk292nM
         5fNmYfr1OkWfAqNGOMC5eVeDkuPgWrrD1KRKO0GqmbcvxtbzHfFl3uxFlYVxOorjxmKp
         5ntNKeFdZRTh8S6UKeqdPtjwerVfHRHuUnlglTKtWBi8oJsyeaGJz9ZiY2/v9NaBQKay
         LNiNUgXTp6hwdnswddDg9GgoiJLAC3ma4cSyVaOMNJ3fS+GkvcbCz4BWVFZ3NhOh4kTl
         nzzfuriFUPbCMUOG//5wQ4nbp3O7mP6o9Vr2DJ65hULFV3POioEbypkEgp/9c1/fCuR5
         i+9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) smtp.mailfrom=richard@nod.at
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:message-id:in-reply-to:references:subject
         :mime-version:content-transfer-encoding:thread-topic:thread-index
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fnu+0NdsTJePCJI+6WoC8cdHSsMRNpGnp+tYr6asV60=;
        b=rlHbdrdIPoR6sqKZ+jpTNa7yzOMo8NrjvGncYRanfJQJ+0u/v37mXBWBFNJ1zt+NGj
         mip32J5rIWxfyN2brBA0ljJfy+5K8s8lY+lr7CMW3wIWVmuv3YzhQhFxhUANOJpUtdu2
         q/U/qkKNXvf0hLD/8vNbkLXE8vEBDDzQwXPBKXgeFcHn++3O0R2RMglzAmJUTdzk0vn8
         LxcXdPTZPYCdWK23mJhzk4SDklzdfPXT1+udx/7x3mHNmHlSdcJAeBfmst8ausXMEFf1
         EA0tJU9EWfykUt7C7vRxBGLKQ0c6MUPnLmA+405DufOuTfaKqFL6SA9+ZBVO7EaKNIE3
         kvFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:message-id:in-reply-to
         :references:subject:mime-version:content-transfer-encoding
         :thread-topic:thread-index:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fnu+0NdsTJePCJI+6WoC8cdHSsMRNpGnp+tYr6asV60=;
        b=nF+dP6E3Zq7R6dO7EK40uW1r/bQrIMP1E8+mjrsNiD4yevqp350y/dfmAMKxLA/CZ0
         fexRWaj3jNNtabOEmb+Be4H4/XA+WDXuk793q1ruZNmJWEwCvqKT9ufzEM1GKKMnUXRZ
         JICUHY17678KeFQBEH+JdkugXvZYYaOKQf77SSw8u2KCCwAY1eqn4qalC0sNLyqlOjnQ
         lh/7C1ezm0MShxMyj871bo3zbwDOnC18wWFjodhIszDNZo+yoSB7of9B6hQA7ok6fJ7U
         SqBE4lnXa3vIGWgTHp6x6JqsJ2lCAWm9Z7VfZ6k+I6b3YWfFF/MBC2jZ60BBfcXKdNPr
         VYlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530uQyXhRL4DCDZEC0wMI/4aLdRNKQ1JK0tiwnM+y/ZjqfRQbed1
	LxdMc2QADjsLIOW3TRyMaes=
X-Google-Smtp-Source: ABdhPJxCFAOBWdzXWV0mUxoqRekRDSdU59YFSoDr1ZIrCJ9VrD5g+iMCRfSwZvTFLTAnZZS+byqryA==
X-Received: by 2002:a1c:6506:: with SMTP id z6mr16933080wmb.55.1607326707002;
        Sun, 06 Dec 2020 23:38:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2d14:: with SMTP id t20ls7742198wmt.3.canary-gmail; Sun,
 06 Dec 2020 23:38:26 -0800 (PST)
X-Received: by 2002:a1c:bc57:: with SMTP id m84mr16768597wmf.163.1607326706098;
        Sun, 06 Dec 2020 23:38:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607326706; cv=none;
        d=google.com; s=arc-20160816;
        b=0Sl5IHcuoZYsbmxzGEwKCYXei9nVFnDyV2O50OguKMgCDGaFMR93AWiaW7Jq+zf58A
         IkHP42Loj3biaKXEzHwUEukedpGA0ELAAJ80FG7UzfAHQoK9TMTatbD8rCfNjIyt7slC
         btAZdR0Qr3nVH4XHcd4zyBzVBV/pZUUu3jYmsOedgs7dy1pwG/oo/meKd/wrjeQd8EMn
         e6GUzQbSHob76hAiqNafvO4CXliadYN0eg2edJzgurDdkQIH8OBIQ7019C0sR4Ob6Qw2
         5ciRiA5bvBA9lzr4W5gFKqY1JQhp+p7cd3sZIezhG+pQ1af9JRb3Z7fNfPw4+h96bRte
         Zv2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=thread-index:thread-topic:content-transfer-encoding:mime-version
         :subject:references:in-reply-to:message-id:cc:to:from:date;
        bh=4hxOiQDTnRuB6BOUHrb4xsmXyrTNQNiW4PN16Q8kC7A=;
        b=U2z41yYh4VAFuCFmNeq1tCsj6luHmvUArN1+IA0wrAkByAu3YgMQsJZbnSuZKI5J3J
         r3x0CIOwfCjsvoxqiM5dGY/sn7UPWj91xxbD4ADHzx0DkEnVtD8qc6lgIR0fLQrlA1IC
         eORtsJ31QsAs1Y0/Ge2SFuzJllLQOkcbEst9Mh6+bxoefdSgQyrKGgvrW00R9I58KVMS
         m5Y8XkO3zjD4cbuXTuokt9q33EE6iPV93mIFesnD4f3HeKxGzMzFlLKYShsw5SnbCSSY
         Z9g1z0Y4VSxHx4ofkQMt6K6x6nFfzZi6kr22BJ0H1pGuMF6joqC/SmELKuD7PJPW6KR1
         chdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) smtp.mailfrom=richard@nod.at
Received: from lithops.sigma-star.at (lithops.sigma-star.at. [195.201.40.130])
        by gmr-mx.google.com with ESMTPS id l3si208812wmg.3.2020.12.06.23.38.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Dec 2020 23:38:25 -0800 (PST)
Received-SPF: pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) client-ip=195.201.40.130;
Received: from localhost (localhost [127.0.0.1])
	by lithops.sigma-star.at (Postfix) with ESMTP id A111460CEF32;
	Mon,  7 Dec 2020 08:38:25 +0100 (CET)
Received: from lithops.sigma-star.at ([127.0.0.1])
	by localhost (lithops.sigma-star.at [127.0.0.1]) (amavisd-new, port 10032)
	with ESMTP id lYe7XNyoDZpR; Mon,  7 Dec 2020 08:38:25 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by lithops.sigma-star.at (Postfix) with ESMTP id 482326231F21;
	Mon,  7 Dec 2020 08:38:25 +0100 (CET)
Received: from lithops.sigma-star.at ([127.0.0.1])
	by localhost (lithops.sigma-star.at [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id Y1hHDwrmG42h; Mon,  7 Dec 2020 08:38:25 +0100 (CET)
Received: from lithops.sigma-star.at (lithops.sigma-star.at [195.201.40.130])
	by lithops.sigma-star.at (Postfix) with ESMTP id 1A58B60CEF32;
	Mon,  7 Dec 2020 08:38:25 +0100 (CET)
Date: Mon, 7 Dec 2020 08:38:24 +0100 (CET)
From: Richard Weinberger <richard@nod.at>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: linux-kernel <linux-kernel@vger.kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Peter Zijlstra <peterz@infradead.org>, tglx <tglx@linutronix.de>
Message-ID: <1460772961.85699.1607326704865.JavaMail.zimbra@nod.at>
In-Reply-To: <20201207043518.GA1819081@boqun-archlinux>
References: <CAFLxGvwienJ7sU2+QAhFt+ywS9iYkbAXDGviuTC-4CVwLOhXfA@mail.gmail.com> <20201207043518.GA1819081@boqun-archlinux>
Subject: Re: BUG: Invalid wait context with KMEMLEAK and KASAN enabled
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [195.201.40.130]
X-Mailer: Zimbra 8.8.12_GA_3807 (ZimbraWebClient - FF78 (Linux)/8.8.12_GA_3809)
Thread-Topic: Invalid wait context with KMEMLEAK and KASAN enabled
Thread-Index: 6g9dKygF4YhpzjznohWxx1ckhTfl2Q==
X-Original-Sender: richard@nod.at
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted
 sender) smtp.mailfrom=richard@nod.at
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

Boqun,

----- Urspr=C3=BCngliche Mail -----
>> Does this ring a bell?
>>=20
>> [    2.298447] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [    2.298971] [ BUG: Invalid wait context ]
>> [    2.298971] 5.10.0-rc6+ #388 Not tainted
>> [    2.298971] -----------------------------
>> [    2.298971] ksoftirqd/1/15 is trying to lock:
>> [    2.298971] ffff888100b94598 (&n->list_lock){....}-{3:3}, at:
>> free_debug_processing+0x3d/0x210
>=20
> I guest you also had CONFIG_PROVE_RAW_LOCK_NESTING=3Dy, right?

Yes, this is the case!

Thanks,
//richard

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1460772961.85699.1607326704865.JavaMail.zimbra%40nod.at.
