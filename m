Return-Path: <kasan-dev+bncBAABBHUASHWQKGQEJSP4PPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 132B0D5EE1
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 11:30:08 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id s139sf13011660pfc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 02:30:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571045406; cv=pass;
        d=google.com; s=arc-20160816;
        b=dr3JZZ44l2vFeO6tPJZEakoIh2KEh8uMasDWLMMwbhIh8Mb7u042ECZ1YDaVjlfyGM
         S/7zDnBi/0ybevva7YEyI4RDo8+tIiItF8SR157WTHM0eXD2AFdgtN0q0xc6WHPXXGoL
         E1E99EYbhyKJM+mIg4JTt1VjjPUR3iOQSdsPaI6iUTQgHxTfV3AbjmUCsyp7DcRVHEKI
         6RW63X3EO1VqCfLWiNwkT9MMtL2DL+8ndxemNotsjLqzd8TL28YnxCTsNkaLGmEe/qXz
         uNk4S43r7EOMDWo91tMQDX29p24xn9b3foz6z7HEM2LLPeQBWH695QPdhPyLrakueUKj
         xzOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:thread-index
         :content-transfer-encoding:mime-version:message-id:date:subject
         :in-reply-to:references:cc:to:from:dmarc-filter:sender
         :dkim-signature;
        bh=ygW8FYoMqHcP9eXo7k639fJHZFE8PKuVXRl0LGZscY0=;
        b=QK7j7srDygzDCP0DqQOszXLEPqrujc5XwX1kR+VDbGpxQ35vUwVr6YIs0Q5PUl0AJ+
         VmWpyy6c/pIpk6S3M56JPib3am1a/UNJ302x3TQKkjhz8uBUN7D/+UBHFqsF2/hNHhzx
         uGrMUOmdQiSkd5J8RpewoxbGDGiwgNuPEYmERYyRsw4c3OL6Uw5MZiZAtiNFP4QXavyW
         cd4z4Kv99Le9i2sTwpwFE6RKt5fDmLcry7r+bgaiV0uzu0sNgKAcqTAo3noD/dhedZKO
         5vkMSRiXivO5AX4MfFB3RSOpaiGFIqvvkcxtpYE715ZXRBX+sHyc4DZK5CedffOFz9Jj
         FkeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codeaurora.org header.s=default header.b=dJLj5RVT;
       dkim=pass header.i=@codeaurora.org header.s=default header.b=S+kstYHv;
       spf=pass (google.com: domain of sgrover@codeaurora.org designates 198.145.29.96 as permitted sender) smtp.mailfrom=sgrover@codeaurora.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dmarc-filter:from:to:cc:references:in-reply-to:subject:date
         :message-id:mime-version:content-transfer-encoding:thread-index
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ygW8FYoMqHcP9eXo7k639fJHZFE8PKuVXRl0LGZscY0=;
        b=pn4eoNDZNxP7TC/9c69MwXfFbNo7GBGCWWq3Ka/NDEbnrxCCuvs2fSWB0P2y+oHx9y
         B42gIODyO/Rt180RNvXBGfY7fznVx3v5qt4dgZkDFKLx8H1UyIuR4hagxFWmyavOdb5G
         XlqtHxjAe+xKzfP1v7WH2NRhWVak1RfefWNUQls+p7BNaG8NZzDJkxMri2sAi2iHg+NZ
         jzfdSIalzlsQCqI3sFtysbNe1EPPmox7wQj30YRK7lVeFidYUBk1JKNANBbDXyE451ru
         rl1J3+3cPqKXvcnei/FCBKWaRsj/EsP6mm4gDHfYaex35XhvzoMq9Rkcl61/lZEv7rdz
         gz9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dmarc-filter:from:to:cc:references
         :in-reply-to:subject:date:message-id:mime-version
         :content-transfer-encoding:thread-index:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ygW8FYoMqHcP9eXo7k639fJHZFE8PKuVXRl0LGZscY0=;
        b=t/AMZaxmRDT5XFxPkx1P7npgJekUDBuHeLlans51+ceGhepSos7ilwbYI4HfqTWzC6
         u8hoWkJ/muA7O6VDtXLu/rV3JHj37fArrCnBhvIu3TXqGYqM5cnT3QlEbYRW35b/1oFP
         07A138vZokheY67JrHowxBKA889Ve5NhJgW9jsVe9bPWS6Yf2rZnJNG51n346/HfzznQ
         rJXrNl9xIRxGj6rHbXumyG0ywlt3eeLzBHCw5014t8MtAClfxZDMsMcZhHsTlRi7rGDf
         DrCCXaClZrC6vXhKoKCYbG+dML5rxgJwrqWOJcIVEuk0ZRtE7asqG+e3Nudx3PHkJX3w
         WRgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVJow+rKOLA1wwPRuF7VwFSwh0cuuPgM/dht4u5dot7fo3umO3X
	5wbl4TBUJsiolwdQrszuwl0=
X-Google-Smtp-Source: APXvYqyqdRq58WsjO/ysZtQQgulnPb10rToOig3WlLkUi1yLfH/pUv+RPodwA3+rlIF5ADCDGFlNeA==
X-Received: by 2002:a62:38d5:: with SMTP id f204mr13770284pfa.100.1571045406507;
        Mon, 14 Oct 2019 02:30:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b115:: with SMTP id q21ls3889194plr.1.gmail; Mon, 14
 Oct 2019 02:30:06 -0700 (PDT)
X-Received: by 2002:a17:90a:8984:: with SMTP id v4mr35163796pjn.109.1571045406188;
        Mon, 14 Oct 2019 02:30:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571045406; cv=none;
        d=google.com; s=arc-20160816;
        b=zCdeGufVegnSUWqahMnOTRJDJr29vaTyYF3/ajCAhwkXrWLlnH45+qTPe9b5cePNl9
         1YG68EYtpOxMGo2dpNRGb0Z9CV/qzYdhkHskBqbdhwchaaotYw9bJUDYwRCxV+90ouVx
         UVjQRz2PotQZoLHyHDwo8vUGj0e3lYIwM2Gs/oRlBo2s40Bwvi2y6AJic42kfz9co1V0
         NM5JeQIsZoviJFCP8Mr9Qk4dccZrgbkroJBtjzPHEMBCCMsSTanPx+yemkOcwAm5lB7X
         WSpM4eABP8M2+5M0aQEfudTJhzNs+H1A14PKp1jFT+3LUwapKP/6L5XmzOef0F1DmSIC
         Uavw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:thread-index:content-transfer-encoding
         :mime-version:message-id:date:subject:in-reply-to:references:cc:to
         :from:dmarc-filter:dkim-signature:dkim-signature;
        bh=4tXM//LUyG5g+XUIx5WMarfDzddVaiDxZSiBVoU808Q=;
        b=w5qAsovnqTeVgO85KVL8Sn+SOq0TsoXD+xKetc1NJ4BGz/kQiofit1m+EY/dh+9nkc
         fX0jq4tM0fZ53Fp/d6JWa0spJM/poO14JIo4DZ47/1oIsrX7/ffttBSzwCiC3ZJ5PNjl
         ELq1jIIiQu32n+nSfsToUjyp2mn8SERauPYl+vEb6Qt+9sz8pWhtW7ydG70fDfe9ORM4
         qUgOAbLKoiOGd5O8jelvM8hwXnZ+w8kO3lWFVZkQJchDX+MILSFV+kBFI3gLC4DikNL7
         uklVmGwJ4dx9fSkE5sJw+OfqbGKlvjaMeyDnm0NGVbQTBGIiw+5LX3sfHAWm55Jajo/W
         UX6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codeaurora.org header.s=default header.b=dJLj5RVT;
       dkim=pass header.i=@codeaurora.org header.s=default header.b=S+kstYHv;
       spf=pass (google.com: domain of sgrover@codeaurora.org designates 198.145.29.96 as permitted sender) smtp.mailfrom=sgrover@codeaurora.org
Received: from smtp.codeaurora.org (smtp.codeaurora.org. [198.145.29.96])
        by gmr-mx.google.com with ESMTPS id p9si931809pjo.0.2019.10.14.02.30.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Oct 2019 02:30:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of sgrover@codeaurora.org designates 198.145.29.96 as permitted sender) client-ip=198.145.29.96;
Received: by smtp.codeaurora.org (Postfix, from userid 1000)
	id E72C160779; Mon, 14 Oct 2019 09:30:05 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on
	pdx-caf-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-2.7 required=2.0 tests=ALL_TRUSTED,BAYES_00,
	DKIM_INVALID,DKIM_SIGNED,SPF_NONE autolearn=no autolearn_force=no
	version=3.4.0
Received: from Sgrover (blr-c-bdr-fw-01_globalnat_allzones-outside.qualcomm.com [103.229.19.19])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	(Authenticated sender: sgrover@codeaurora.org)
	by smtp.codeaurora.org (Postfix) with ESMTPSA id B0F9B60159;
	Mon, 14 Oct 2019 09:30:01 +0000 (UTC)
DMARC-Filter: OpenDMARC Filter v1.3.2 smtp.codeaurora.org B0F9B60159
From: <sgrover@codeaurora.org>
To: "'Marco Elver'" <elver@google.com>,
	"'Dmitry Vyukov'" <dvyukov@google.com>
Cc: "'kasan-dev'" <kasan-dev@googlegroups.com>,
	"'LKML'" <linux-kernel@vger.kernel.org>,
	"'Paul E. McKenney'" <paulmck@linux.ibm.com>,
	"'Will Deacon'" <willdeacon@google.com>,
	"'Andrea Parri'" <parri.andrea@gmail.com>,
	"'Alan Stern'" <stern@rowland.harvard.edu>,
	"'Mark Rutland'" <mark.rutland@arm.com>
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org> <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com> <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
In-Reply-To: <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
Subject: RE: KCSAN Support on ARM64 Kernel
Date: Mon, 14 Oct 2019 14:59:58 +0530
Message-ID: <002801d58271$f5d01db0$e1705910$@codeaurora.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Mailer: Microsoft Outlook 16.0
Thread-Index: AQIkPOdSLH2Qcxx8ygFmLWl3/QxVtgJ871EyAngelYemlMA6UA==
Content-Language: en-us
X-Original-Sender: sgrover@codeaurora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codeaurora.org header.s=default header.b=dJLj5RVT;       dkim=pass
 header.i=@codeaurora.org header.s=default header.b=S+kstYHv;       spf=pass
 (google.com: domain of sgrover@codeaurora.org designates 198.145.29.96 as
 permitted sender) smtp.mailfrom=sgrover@codeaurora.org
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

Hi Marco,

When can we expect upstream of KCSAN on kernel mainline. Any timeline?

Regards,
Sachin Grover

-----Original Message-----
From: Marco Elver <elver@google.com>=20
Sent: Monday, 14 October, 2019 2:40 PM
To: Dmitry Vyukov <dvyukov@google.com>
Cc: sgrover@codeaurora.org; kasan-dev <kasan-dev@googlegroups.com>; LKML <l=
inux-kernel@vger.kernel.org>; Paul E. McKenney <paulmck@linux.ibm.com>; Wil=
l Deacon <willdeacon@google.com>; Andrea Parri <parri.andrea@gmail.com>; Al=
an Stern <stern@rowland.harvard.edu>; Mark Rutland <mark.rutland@arm.com>
Subject: Re: KCSAN Support on ARM64 Kernel

On Mon, 14 Oct 2019 at 10:40, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Oct 14, 2019 at 7:11 AM <sgrover@codeaurora.org> wrote:
> >
> > Hi Dmitry,
> >
> > I am from Qualcomm Linux Security Team, just going through KCSAN and fo=
und that there was a thread for arm64 support (https://lkml.org/lkml/2019/9=
/20/804).
> >
> > Can you please tell me if KCSAN is supported on ARM64 now? Can I just r=
ebase the KCSAN branch on top of our let=E2=80=99s say android mainline ker=
nel, enable the config and run syzkaller on that for finding race condition=
s?
> >
> > It would be very helpful if you reply, we want to setup this for findin=
g issues on our proprietary modules that are not part of kernel mainline.
> >
> > Regards,
> >
> > Sachin Grover
>
> +more people re KCSAN on ARM64

KCSAN does not yet have ARM64 support. Once it's upstream, I would expect t=
hat Mark's patches (from repo linked in LKML thread) will just cleanly appl=
y to enable ARM64 support.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/002801d58271%24f5d01db0%24e1705910%24%40codeaurora.org.
