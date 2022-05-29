Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBNPHZ2KAMGQESDPOIQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 790BE5371F4
	for <lists+kasan-dev@lfdr.de>; Sun, 29 May 2022 19:56:06 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id bi27-20020a0565120e9b00b004786caccc7dsf4203782lfb.11
        for <lists+kasan-dev@lfdr.de>; Sun, 29 May 2022 10:56:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653846966; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZU5/T8k2rzz/JvMA0/ZbYrP8U8qb6FUYMQbnB4YWHieX+xX1InTz3Nn6AHkcJdBBZq
         me4qXiiR3ZA0mw3hXbN5cP9qTZ7Eind318Wn+0g4W7luluvg7/yHPIh3VM/rnv5B8CUS
         BU4/gSNPli0KO0wTBIcm9XcO0QhC9IspjsDVnC8qOVXOHmdZYqwpxvsyek0PBqghfzGl
         eEMSE6o6DwPUT0L9/PfX8qNCrqC7s1QYUvLg3h8Dhtx7rnAfyN6uJjjh8BpkY91D7bPo
         kBIJvwzNmfNsLPR4V+rQbI95jLtE7+ro4dsIHgDPtMBWo3/LKWb9xa/8mywXzzUpIlds
         fAIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=SvCxWPtvyRPX3qmlJTfz1XHQMhhTaXzl5Nipou4Zq4I=;
        b=N2BS4MXv3fktsXTE2iF1DnMa5qqQvw953x+w6OV1EnpVgUrzWlaP3/KakVoNlwpgH3
         4CWKmd5/wxIg4bom13TI0y8ebyb/npgaT7oar0I5fAjSM+oWwMtqwrYcvHjpciVT9gmS
         xSIyg8e0cwTFq7E/JxRRS2ygLzSstQE23yH9cTHWs4Nu8Jrr7WPHykDLgZ/sqd1Ehs9x
         8Qz6alXXnq1HfBS8GiP7whp2xkgB7wIbBAi3hox9JrpHFaJbUFfdoJeA0bMnXez+KppB
         QS14kFZjFKaQTNVj1Utzk1mM9h/X9LKLEH+BglWcIAVzOpGY0nw1nc03aBZ0MbR9FtgL
         /Tvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b="sLMBlu/m";
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SvCxWPtvyRPX3qmlJTfz1XHQMhhTaXzl5Nipou4Zq4I=;
        b=LvNSyJVcPkf9242SwSNyjjZR3ghhkuawK5hT7aG7AKdtHxJuyPsIPI64gQK6RUbupp
         gEcZddKc68EBHqAKfAHiBgzuAWUaQSgcD34wcfhn9KhBz4gSCvj+eFxhQehR1JqPT78e
         qOIjL8dYjim6pmqxW0SDoP4dhYp0/FCHH6O8LX6ZdskNvxwEF4rqC7jMkzXmEfjyV34D
         NKbLdMownueM9TCLrrbq92eT7HYVGD/m2kONWXUsqtxie5w4tXdFMkyfagNMO0W0z2/a
         Jj9LPnMCPA9lDX+nSNPdVhrdIHZlCgaIqyPrReOfKnbm9LdWMXIBx09BmVm4tHx3Y18j
         +fpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SvCxWPtvyRPX3qmlJTfz1XHQMhhTaXzl5Nipou4Zq4I=;
        b=1c5ejvTjlw0xIMcKZs1lgk08i68zKLdLjBm07NAw7lyzDgZyoLFtnscZhF9uS38cKk
         gVHdRnuMvQtEL6mjw/OyqH/iVntHfSeqaG6Iu+5kJ3DyvJ3ac/d/BMbovXHpGn5iwlZk
         dDhSBmZ60ijMv65YrD62rHTxq4FFNYP8glt4bzjgl9uvNYX3wHt5rGWR81bEGMoGccrB
         I0ou7k8jfH6gJX/tCDsVZhe6lLpQtHGJfCvW2konlch6HZTkd3CTxgQChELEJ1XK7/uT
         0QbMqtCk1TWh38Jf4+F/8t4QoDgzO2Soo8Y3u0E3timB2HvugLf/aR8WOS3jRVkvfxVi
         U76g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530L4eqGalLUTeFCi9ox9wjo1U0Ny6+SxGfVJqdo/AQeRjygDLma
	5LjOMlkks1oszmgjTT/2mBU=
X-Google-Smtp-Source: ABdhPJx3S8pjzCutWkY6aV/HIEpSkp5KjqijClEwmYo4oHtS09I81hJiaoRFymAA6Wr5tjC7U1Hy2A==
X-Received: by 2002:a2e:a4c7:0:b0:255:4b85:c371 with SMTP id p7-20020a2ea4c7000000b002554b85c371mr3416382ljm.260.1653846965608;
        Sun, 29 May 2022 10:56:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als3632507lfa.2.gmail; Sun, 29 May 2022
 10:56:04 -0700 (PDT)
X-Received: by 2002:a05:6512:3f0e:b0:478:67ff:9083 with SMTP id y14-20020a0565123f0e00b0047867ff9083mr27597770lfa.96.1653846964345;
        Sun, 29 May 2022 10:56:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653846964; cv=none;
        d=google.com; s=arc-20160816;
        b=SalXh6QcfgPuuzxiMh+sZhAmKcNENDWt3W4DqcYs5FkOwqhYL4SmFch0vqtVYpjw5h
         8U5lalmMqSY+L7+z4DX2SfUjGuVcBVf8rKRSdDVuO2Ul4dbnH8eqfaoLuS3kHtzZb/NT
         +kpy32g3FAjnYYRbcmnzcFZvFqo2Icd5SyV541ZLHpS3CNCd1s97+W8Co9Y1ngvhMLPw
         z9x5yNrJ4RTY8p9GocwufEj6I0iRPtOE5Oeej+rMBCF5npx4M9twB/+CqoNyK1BbToIq
         goozDUltujOmeFurtfejvFka9UyfABlY9J8RhSdsKHe7ELSq0Ae1oddYnJYc9kR9cVN1
         IA+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=190r9qJwFvNNRiNpmHW+00h4gKYz6/hvhNKsg+u9ISs=;
        b=lTszspzEBI9vb8OS+YW6WkOlH00G5moC6+Kl5i3syPj+5u8lmAFDFOMWTNMf3UEqHR
         KrJt13+w82Q2K2qPVrMSe3o7XiTm9B+of2AYfoi/6d04DkcSCWN/Pkn7agsMPDi91bB2
         pgE/sbcZP9ukPQAVjmH+S7nmbIRf7rMXjeEupK4PYLChPZs8INU3bo29l7YgUJokVlYr
         4YZ0+sOuYgevV7AbqhgcNveOD6h+xGx7EnbbOO/UFASqT8OCMci5Z5B/PtZKkwidEuAA
         /ZWXlvYpHtll5eY6kdUDCti9NBnTkJrXZ/LwDjmEKWtETHTgbNYpjGUuN4n526GdvD2+
         2GeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b="sLMBlu/m";
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id h12-20020a05651c124c00b0024eee872899si440333ljh.0.2022.05.29.10.56.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 29 May 2022 10:56:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nvN8w-007nhJ-9k;
	Sun, 29 May 2022 19:55:58 +0200
Message-ID: <b65bd540eae2e593f6d9eb21b6c7d9a06a2809fb.camel@sipsolutions.net>
Subject: Re: [PATCH v2 2/2] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Dmitry Vyukov <dvyukov@google.com>,
 Brendan Higgins <brendanhiggins@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org,
 LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
 linux-mm@kvack.org
Date: Sun, 29 May 2022 19:55:57 +0200
In-Reply-To: <de38a6b852d31cbe123d033965dbd9b662d29a76.camel@sipsolutions.net>
References: <20220527185600.1236769-1-davidgow@google.com>
	 <20220527185600.1236769-2-davidgow@google.com>
	 <de38a6b852d31cbe123d033965dbd9b662d29a76.camel@sipsolutions.net>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b="sLMBlu/m";       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2022-05-27 at 22:14 +0200, Johannes Berg wrote:
> On Fri, 2022-05-27 at 11:56 -0700, David Gow wrote:
> > 
> > This is v2 of the KASAN/UML port. It should be ready to go.
> 
> Nice, thanks a lot! :)
> 
> > It does benefit significantly from the following patches:
> > - Bugfix for memory corruption, needed for KASAN_STACK support:
> > https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
> 
> Btw, oddly enough, I don't seem to actually see this (tried gcc 10.3 and
> 11.3 so far) - is there anything you know about compiler versions
> related to this perhaps? Or clang only?
> 

I do see it on gcc (Debian 10.2.1-6) 10.2.1 20210110, but that was a
different .config too ... strange.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b65bd540eae2e593f6d9eb21b6c7d9a06a2809fb.camel%40sipsolutions.net.
