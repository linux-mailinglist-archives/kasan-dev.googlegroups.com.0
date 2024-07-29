Return-Path: <kasan-dev+bncBDVLLAFZXUORBIVETW2QMGQEMIIJY2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 47FB493EFDA
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 10:26:12 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-52f0258afecsf3783352e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 01:26:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722241571; cv=pass;
        d=google.com; s=arc-20160816;
        b=MUWJ8q+rLRGZVXU+YEpmZJZHUKsNWaaLOr+1tPXraA4kBeu23XpuP2kUnvDRclWEAM
         CPTIE7NHGv2rbm5yPDKfQgcsKvnqOFFxdT4bBE4fdVmR4MPhu4OoBsC4AFrVInDPVFHe
         kjxUIm2D9SB/Tc/PCrIFMs+9RH8VTL3cYcgZOUaEjVmEb52/PsgpaEX+FLIBiDbfiNqy
         O8AF5aFKSDStFlvwAczNULtt0MGha3Ki06ibY/LVAfZ0MKW8vzk2rXlUmhf2BqgS9I7y
         7YFQeQvCNwi7qsWp7B4vqHmNO24Z/zfM/2nhZbOKWvfjHyPPI46tJXjQnBMfAaM8IRC2
         WLXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:autocrypt:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=J1+0sqqR52d4VlWut+Y5y2Fsyhhk627d1MqTA2kXBi8=;
        fh=Lz2TEKlcu5FmWL1fRbnd0dxqigShyapjplgOMaUONJQ=;
        b=v/bsPjtwpI4qM8VLIN6i0ZbWPdylP1eC8/SdIknAHa4bkbLQGbq7FigH0Z09HyY5SF
         /xlT6sEtoHigDr7h9kVKhpMtd3Z9m6hOom5hKQnkxV6+/20BjppeOZDcc7d9cJ91XC4F
         y12sfBpH6IkwHsLCy3/ao6r2a2mFGRFQFbSfID1K+e040rSPU4w7jXhvKOUHFvrY+agn
         QBx7jqeVbXDAsLfY0MdSnwSk1ZWwuSmOrk5ol3dgNuDMM14b/LnvbtA9udQEFNn2aguc
         by0teqX7jJ3xJSHrYP9WU98MdfH5kBnwU2FiA+cKgJz6z6CFgkv7HXM3ywzH8dKBNgpp
         JLOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sylv.io header.s=MBO0001 header.b=DU9eH44o;
       spf=pass (google.com: domain of sylv@sylv.io designates 80.241.56.171 as permitted sender) smtp.mailfrom=sylv@sylv.io;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=sylv.io
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722241571; x=1722846371; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:autocrypt:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J1+0sqqR52d4VlWut+Y5y2Fsyhhk627d1MqTA2kXBi8=;
        b=MQ7omtmqXH9bVBVeCIoDF87i0JJWEqKPSbNtGKDTe3I6HTF1OvQFkyXg3ygca1Gw5g
         QDmC/hqrB39AAq8Jxk3kdkUwJIWqwp46c8UOlPXk36y8Fz9T6dTOL7l62F+N0Cnxv5RX
         U900Tl03C/axJ05fKfGVUlqhD/GtFowhThQn/T0BJutvsbPzK3UIorM+zgcKs9v/8i7e
         +kuPl/JLKYEYa80tWHEFhtv/uCKEKiJ72eqbU8ChCwQ6lVkN7s6NJyp4W4vDUJL4JkE4
         n7RgokWiuK8bMneBnJUlC3JBnSmC2iuoxcmHnhwkZ0iSPVrYJzuOnfrjAIHOR7v06Ut+
         DH9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722241571; x=1722846371;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :autocrypt:references:in-reply-to:date:cc:to:from:subject:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J1+0sqqR52d4VlWut+Y5y2Fsyhhk627d1MqTA2kXBi8=;
        b=UuPCfCtWNTwgkvIFUtPe+eDQRx444Bw2WNaL29J7XpKrQjNRgdzGzdCSBaV4TrJWvg
         pH2lYM4cmoJ3I7FS35ppxsdygOXLgoX8ub0ixqnSQ+4cc5rklmGT0oDQ3+tvKw/GBqLw
         DTEC+xiGnxhzaJyidRpu6ZNnGv5PQg0aH5Dy2AtM6Iml1rkAFpWN/hVYY0sFcWn3k1lk
         ZIC8OFidZfOUWQAuMRe7C1xeHI2V4p2hNiU3qevnmB9gvW7wUVRCTEeFH945PNHaC8IW
         GCTweYmfa0BkEdaqxY4yw6KPq71bImXhPM1ridKtz755kW/5UN65UdzfpQFELluLd0Ot
         UEeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8utxSX3w+3MhPrSgHXtr5BVGzrIIrYNsUziHBLLw52zlmt0vZMX5TfWabFi2NcEotcuJiB2j+qi8TV1MOg5LJgm9G2HUrZg==
X-Gm-Message-State: AOJu0YxDosQLCD91tn/HnA4dJj3bre20Mx6f7lpoV20VAixnV2XLOlkt
	1QIl2QA88lU+Qz4yVtxbkw4F5GKmqKo6OY0sCj2s2zXZAmHFn1RR
X-Google-Smtp-Source: AGHT+IHCrknXE/Y2w2cWPSBBZLQLPAMurS73Lim6p+ih63q1h/aZ+mc/zYAK2e4sok7DTDo8QvGBtQ==
X-Received: by 2002:a2e:9608:0:b0:2ef:2443:ac8c with SMTP id 38308e7fff4ca-2f12ee422eemr43073491fa.31.1722241570774;
        Mon, 29 Jul 2024 01:26:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a989:0:b0:2ec:5941:b0cb with SMTP id 38308e7fff4ca-2f03aa64559ls276291fa.1.-pod-prod-04-eu;
 Mon, 29 Jul 2024 01:26:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuN+vkyI+kyveEO1qA0W5aAKks52GLSzf5LWGRIaRIL9jox/+2LJkzSrCmY+8uWRy8Z7c80WwmWFtvr2n0v5iXCf0AxpHppEmykw==
X-Received: by 2002:a2e:9d98:0:b0:2ef:2e90:29f9 with SMTP id 38308e7fff4ca-2f12edfd79dmr45749171fa.17.1722241568618;
        Mon, 29 Jul 2024 01:26:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722241568; cv=none;
        d=google.com; s=arc-20160816;
        b=NMFSpli1RZIlpA0A5uyL1kGaxERg9mstVms8xEf4vOLyA7QsqRuVW+al0DcKE7bjrz
         1Yx2LF2jK0dI7JZdtF0HBSA3JpXaenP3hzj92ZgC8hVr45rnEOE3neIGWgdT5aKZQ1iX
         Eg9Td7y0b9CETJ5U3mFglYI5gJRbeOBaKip/OF37uKvIIzmE36E8leFBInKHdlMJshi6
         bTseYkny9AjjRWhwmrudxpPPO/oUTT2TDAvNKiaaIDYOrpysU/9s9AcVyhDQRtw63KgL
         CdJ8tuYt/br3GXiiyunt3OUhjCIzcvQC5Uuu8tDGc1JCBn0j1PTZ1YEdX6jsxxL6GbR7
         9+/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:autocrypt:references:in-reply-to:date:cc:to:from
         :subject:message-id:dkim-signature;
        bh=K7fnqw37rhxeqjvTfmqBdiz93kBqO/8jFv9TVqAzuSI=;
        fh=jX8fXXqQ8/YHkyR2yk9JhmDF86K2RvTNTl5PPrj+TcQ=;
        b=B1FWFcHMrIMHuwnkZCxfCv41jVKl/8CsFBB9vcIascAoZC+6qEusEYT6CNFyTUfcU+
         8GLQWzmzi+W9OjKf0VSZxVAZ6nmXXSUXWh38fZFPIrHHd/ib1PxKXmMV+c1N/t6SbxzM
         8SHC/cY4W5H8k1zDTxP37feV3EOA86HKfB0+WfMTgrwf1GoU+Pzwh4KfKK10jXkRJthn
         Gm84GPW2nkXPZUbfrQOgB+1MKqxqp5fmq8HWUGvx2sFl72Cd1BAEwdljRddmpp6O+pxb
         znYCq2G2Qx4RBnl/y39Rm05syEA9I21owWEkt1bHtsXbZRvBK/q1E//OUotmfTVOEouq
         cFUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sylv.io header.s=MBO0001 header.b=DU9eH44o;
       spf=pass (google.com: domain of sylv@sylv.io designates 80.241.56.171 as permitted sender) smtp.mailfrom=sylv@sylv.io;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=sylv.io
Received: from mout-p-201.mailbox.org (mout-p-201.mailbox.org. [80.241.56.171])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42806c76337si2468825e9.0.2024.07.29.01.26.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jul 2024 01:26:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of sylv@sylv.io designates 80.241.56.171 as permitted sender) client-ip=80.241.56.171;
Received: from smtp202.mailbox.org (smtp202.mailbox.org [IPv6:2001:67c:2050:b231:465::202])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mout-p-201.mailbox.org (Postfix) with ESMTPS id 4WXWf55JDkz9tJ5;
	Mon, 29 Jul 2024 10:26:05 +0200 (CEST)
Message-ID: <baae33f5602d8bcd38b48cd6ea4617c8e17d8650.camel@sylv.io>
Subject: Re: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in
 softirq context
From: Marcello Sylvester Bauer <sylv@sylv.io>
To: andrey.konovalov@linux.dev, Alan Stern <stern@rowland.harvard.edu>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>,  Aleksandr Nogikh <nogikh@google.com>, Marco Elver
 <elver@google.com>, Alexander Potapenko <glider@google.com>,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 linux-mm@kvack.org, linux-usb@vger.kernel.org, 
 linux-kernel@vger.kernel.org, 
 syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com, 
 syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com,
 stable@vger.kernel.org
Date: Mon, 29 Jul 2024 10:25:56 +0200
In-Reply-To: <20240729022316.92219-1-andrey.konovalov@linux.dev>
References: <20240729022316.92219-1-andrey.konovalov@linux.dev>
Autocrypt: addr=sylv@sylv.io; prefer-encrypt=mutual;
 keydata=mDMEX4a2/RYJKwYBBAHaRw8BAQdAgPh7hXqL35bMLhbhZbzNFhQslzLjFA/nooSPkjfwp
 1y0J01hcmNlbGxvIFN5bHZlc3RlciBCYXVlciA8c3lsdkBzeWx2LmlvPoiRBBMWCgA5AhsBBAsJCA
 cEFQoJCAUWAgMBAAIeAQIXgBYhBAzRGzXUX6FMlUr5GUv0FpMH/RIkBQJfhrn3AhkBAAoJEEv0FpM
 H/RIk+XAA/2uYBupPaP7oiwvwRjhAnO5wAZzQh8guHu3CDiLTUnXNAQDjeHY1ES/IXN6W+gVfGPFa
 rtzmGeRUQk1lSQL7SfhwCbQvTWFyY2VsbG8gU3lsdmVzdGVyIEJhdWVyIDxtZUBtYXJjZWxsb2Jhd
 WVyLmNvbT6IjgQTFgoANhYhBAzRGzXUX6FMlUr5GUv0FpMH/RIkBQJfhrlYAhsBBAsJCAcEFQoJCA
 UWAgMBAAIeAQIXgAAKCRBL9BaTB/0SJOHbAQCp2E6WRbY3U7nxxfEt8lOq3pCi0VeUAWu93CnWZX0
 X9wEArZ6h9wCGHhlGBTaB/U7BRHlgftCcEuxeCuMZEa8rqwC0MU1hcmNlbGxvIFN5bHZlc3RlciBC
 YXVlciA8aW5mb0BtYXJjZWxsb2JhdWVyLmNvbT6IjgQTFgoANhYhBAzRGzXUX6FMlUr5GUv0FpMH/
 RIkBQJfhrmFAhsBBAsJCAcEFQoJCAUWAgMBAAIeAQIXgAAKCRBL9BaTB/0SJLF/AQDwn+Oiv2Zf2o
 ZxGttQl/oQNR3YJZuGt8k+JTSWS98xxwEAiBULaSCQ4JaVq5VdOXwb0tPsfQuYbBQjbAK9WI3QmwM=
Content-Type: multipart/signed; micalg="pgp-sha512";
	protocol="application/pgp-signature"; boundary="=-LWyd7UgxwvTeqjduYLti"
MIME-Version: 1.0
X-Rspamd-Queue-Id: 4WXWf55JDkz9tJ5
X-Original-Sender: sylv@sylv.io
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sylv.io header.s=MBO0001 header.b=DU9eH44o;       spf=pass
 (google.com: domain of sylv@sylv.io designates 80.241.56.171 as permitted
 sender) smtp.mailfrom=sylv@sylv.io;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=sylv.io
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


--=-LWyd7UgxwvTeqjduYLti
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi Andrey,

On Mon, 2024-07-29 at 04:23 +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@gmail.com>
>=20
> Commit a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer
> transfer
> scheduler") switched dummy_hcd to use hrtimer and made the timer's
> callback be executed in the hardirq context.
>=20
> With that change, __usb_hcd_giveback_urb now gets executed in the
> hardirq
> context, which causes problems for KCOV and KMSAN.
>=20
> One problem is that KCOV now is unable to collect coverage from
> the USB code that gets executed from the dummy_hcd's timer callback,
> as KCOV cannot collect coverage in the hardirq context.
>=20
> Another problem is that the dummy_hcd hrtimer might get triggered in
> the
> middle of a softirq with KCOV remote coverage collection enabled, and
> that
> causes a WARNING in KCOV, as reported by syzbot. (I sent a separate
> patch
> to shut down this WARNING, but that doesn't fix the other two
> issues.)
>=20
> Finally, KMSAN appears to ignore tracking memory copying operations
> that happen in the hardirq context, which causes false positive
> kernel-infoleaks, as reported by syzbot.
>=20
> Change the hrtimer in dummy_hcd to execute the callback in the
> softirq
> context.
>=20
> Reported-by: syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3D2388cdaeb6b10f0c13ac
> Reported-by: syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3D17ca2339e34a1d863aad
> Fixes: a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer
> transfer scheduler")
> Cc: stable@vger.kernel.org
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
>=20
> ---
>=20
> Marcello, would this change be acceptable for your use case?

Thanks for investigating and finding the cause of this problem. I have
already submitted an identical patch to change the hrtimer to softirq:
https://lkml.org/lkml/2024/6/26/969

However, your commit messages contain more useful information about the
problem at hand. So I'm happy to drop my patch in favor of yours.

Btw, the same problem has also been reported by the intel kernel test
robot. So we should add additional tags to mark this patch as the fix.


Reported-by: kernel test robot <oliver.sang@intel.com>
Closes:
https://lore.kernel.org/oe-lkp/202406141323.413a90d2-lkp@intel.com
Acked-by: Marcello Sylvester Bauer <sylv@sylv.io>

Thanks,
Marcello

> If we wanted to keep the hardirq hrtimer, we would need teach KCOV to
> collect coverage in the hardirq context (or disable it, which would
> be
> unfortunate) and also fix whatever is wrong with KMSAN, but all that
> requires some work.
> ---
> =C2=A0drivers/usb/gadget/udc/dummy_hcd.c | 14 ++++++++------
> =C2=A01 file changed, 8 insertions(+), 6 deletions(-)
>=20
> diff --git a/drivers/usb/gadget/udc/dummy_hcd.c
> b/drivers/usb/gadget/udc/dummy_hcd.c
> index f37b0d8386c1a..ff7bee78bcc49 100644
> --- a/drivers/usb/gadget/udc/dummy_hcd.c
> +++ b/drivers/usb/gadget/udc/dummy_hcd.c
> @@ -1304,7 +1304,8 @@ static int dummy_urb_enqueue(
> =C2=A0
> =C2=A0 /* kick the scheduler, it'll do the rest */
> =C2=A0 if (!hrtimer_active(&dum_hcd->timer))
> - hrtimer_start(&dum_hcd->timer, ns_to_ktime(DUMMY_TIMER_INT_NSECS),
> HRTIMER_MODE_REL);
> + hrtimer_start(&dum_hcd->timer, ns_to_ktime(DUMMY_TIMER_INT_NSECS),
> + HRTIMER_MODE_REL_SOFT);
> =C2=A0
> =C2=A0 done:
> =C2=A0 spin_unlock_irqrestore(&dum_hcd->dum->lock, flags);
> @@ -1325,7 +1326,7 @@ static int dummy_urb_dequeue(struct usb_hcd
> *hcd, struct urb *urb, int status)
> =C2=A0 rc =3D usb_hcd_check_unlink_urb(hcd, urb, status);
> =C2=A0 if (!rc && dum_hcd->rh_state !=3D DUMMY_RH_RUNNING &&
> =C2=A0 !list_empty(&dum_hcd->urbp_list))
> - hrtimer_start(&dum_hcd->timer, ns_to_ktime(0), HRTIMER_MODE_REL);
> + hrtimer_start(&dum_hcd->timer, ns_to_ktime(0),
> HRTIMER_MODE_REL_SOFT);
> =C2=A0
> =C2=A0 spin_unlock_irqrestore(&dum_hcd->dum->lock, flags);
> =C2=A0 return rc;
> @@ -1995,7 +1996,8 @@ static enum hrtimer_restart dummy_timer(struct
> hrtimer *t)
> =C2=A0 dum_hcd->udev =3D NULL;
> =C2=A0 } else if (dum_hcd->rh_state =3D=3D DUMMY_RH_RUNNING) {
> =C2=A0 /* want a 1 msec delay here */
> - hrtimer_start(&dum_hcd->timer, ns_to_ktime(DUMMY_TIMER_INT_NSECS),
> HRTIMER_MODE_REL);
> + hrtimer_start(&dum_hcd->timer, ns_to_ktime(DUMMY_TIMER_INT_NSECS),
> + HRTIMER_MODE_REL_SOFT);
> =C2=A0 }
> =C2=A0
> =C2=A0 spin_unlock_irqrestore(&dum->lock, flags);
> @@ -2389,7 +2391,7 @@ static int dummy_bus_resume(struct usb_hcd
> *hcd)
> =C2=A0 dum_hcd->rh_state =3D DUMMY_RH_RUNNING;
> =C2=A0 set_link_state(dum_hcd);
> =C2=A0 if (!list_empty(&dum_hcd->urbp_list))
> - hrtimer_start(&dum_hcd->timer, ns_to_ktime(0), HRTIMER_MODE_REL);
> + hrtimer_start(&dum_hcd->timer, ns_to_ktime(0),
> HRTIMER_MODE_REL_SOFT);
> =C2=A0 hcd->state =3D HC_STATE_RUNNING;
> =C2=A0 }
> =C2=A0 spin_unlock_irq(&dum_hcd->dum->lock);
> @@ -2467,7 +2469,7 @@ static DEVICE_ATTR_RO(urbs);
> =C2=A0
> =C2=A0static int dummy_start_ss(struct dummy_hcd *dum_hcd)
> =C2=A0{
> - hrtimer_init(&dum_hcd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
> + hrtimer_init(&dum_hcd->timer, CLOCK_MONOTONIC,
> HRTIMER_MODE_REL_SOFT);
> =C2=A0 dum_hcd->timer.function =3D dummy_timer;
> =C2=A0 dum_hcd->rh_state =3D DUMMY_RH_RUNNING;
> =C2=A0 dum_hcd->stream_en_ep =3D 0;
> @@ -2497,7 +2499,7 @@ static int dummy_start(struct usb_hcd *hcd)
> =C2=A0 return dummy_start_ss(dum_hcd);
> =C2=A0
> =C2=A0 spin_lock_init(&dum_hcd->dum->lock);
> - hrtimer_init(&dum_hcd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
> + hrtimer_init(&dum_hcd->timer, CLOCK_MONOTONIC,
> HRTIMER_MODE_REL_SOFT);
> =C2=A0 dum_hcd->timer.function =3D dummy_timer;
> =C2=A0 dum_hcd->rh_state =3D DUMMY_RH_RUNNING;
> =C2=A0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/baae33f5602d8bcd38b48cd6ea4617c8e17d8650.camel%40sylv.io.

--=-LWyd7UgxwvTeqjduYLti
Content-Type: application/pgp-signature; name="signature.asc"
Content-Description: This is a digitally signed message part

-----BEGIN PGP SIGNATURE-----

iIMEABYKACsWIQR81eCeIFvseLvKEUNWslSZtA36GQUCZqdSFA0cc3lsdkBzeWx2
LmlvAAoJEFayVJm0DfoZT9wA/0cbEIRrGeccZCTVN5CQK6Nx31rSKXTIDsobIdO0
9cG/AQDGFJq2QwpbDTAe4HN2gmybrc3qqnu5zQ/qym81WTu1BA==
=hqtW
-----END PGP SIGNATURE-----

--=-LWyd7UgxwvTeqjduYLti--
