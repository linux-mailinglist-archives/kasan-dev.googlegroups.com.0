Return-Path: <kasan-dev+bncBCKPFB7SXUERBRVNZPEQMGQEPHNBTUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 421B8CA7A9E
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 13:57:44 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-4509d3ce317sf1341143b6e.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 04:57:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764939462; cv=pass;
        d=google.com; s=arc-20240605;
        b=P/H40gGhmz1Nswwa5QXovJNPXUCDji9QAhTuak+zcIafK+uqCak0wf0k68X2NS6HFD
         qawVwUgPUbWXnMamsj4GOsS5gN/3x1fecDpHksgGkoka3rp3fTlghp0JlXN+h8rztIsu
         GzvUAlhgJ3cAydBBgyi620GiAvzdHFTK8gCWoGw/hwdb3RxZ5FrDSXwOer3Bx5PK3i/W
         5gYH/uQdfb5mPxJA3XVVvNLGjTxHZ21Rhm8hdW0EX9cpsa1ivwt94RpalEjilQiaBBtB
         jUGDe/hVdXK2JQ1khx74t5267jDGKWhhO7DPh9ScnpaicKVPMIMq8/E3S5S3JXgaIRvX
         otMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WMYH4E8BH/NUQS8gK0UExCExJBYLbSherGDRMBsMdDk=;
        fh=z/q8PP7NIIU5x5k7HZoRU9TmNoGfd9YTX4uHj9Cu1/g=;
        b=ds92zB7BFWbN0OXqBb+gyEqp2HbjBSYFxpltqhfWB3OkyZ56WjxCrPGo3RkcMpmg/Q
         tyFmSuhB6gG3kDfTIsSW0LW0z3mORMRvK/t0sndhWMQoF8jbSJylVE08wHN//QxGZPBZ
         m1Ucv/mz0Gudow0PKX/nNBU/95CGuDXcdKL9yhFaFdco9ZBtKAWygGAlnerrSvUSuIUf
         I28gPA4bntE5V9qV8OX3Y7pr2Dx51u4OqrhekeCm5DQ7pNq/ssHSECYS+MnIqfXiftOS
         v+ioXQLcnW5wCkt+hjt7EiQnPSpwtOEA4z9bIsV2Up21mGz1U2dTSbp5UAg7Pv7kUgB/
         JOcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JvuKEFum;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764939462; x=1765544262; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=WMYH4E8BH/NUQS8gK0UExCExJBYLbSherGDRMBsMdDk=;
        b=DbNwBiDLjjakkCE0TUievsPuZ2wpc2xKzlDimuWSrwOTVBXvRNuA76rkjmhF9+w8ig
         QB2WsT2ht6qHLY6bntXoktD+1efjuLx+dDk0SZVKY5dUha55eoEaNxrbE6vq4aFUEN/5
         krY6Y0kt/HE8HDtlZ1X3VzmA+zxprcsYPaWQZ2VN5E0A51uJLmTYJhkzYAmLR/gUBjuS
         HpGlMZvm2TMohk+tVJWPYrYTOZiTgVnhorwIs7VfdffH1+3ZCesyAYLiN+3GxuMMISuK
         tMhXdaGA2jjUY/7NF9jj5eP7eoHLNFqos+oHpjzzFgkINMXAY+E74xdfZCLIveFD0xYE
         7+Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764939462; x=1765544262;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=WMYH4E8BH/NUQS8gK0UExCExJBYLbSherGDRMBsMdDk=;
        b=WR6CYsWr385Dkgk4d3sTmGP1Sd62VHO4TtYC7Rw1ANViioX/yfHwaGzfJXXRPiXRen
         NpAtaI7dzq6EylZXG0Ciqd4vxC6UBEKz4MZxbUdBtVukG1VYERSWN78hLGxuT63MYx+d
         3r57v+P6b+6Aytn/3ZH7OrGIJghM1WdUXwFZDI1jiFP6VJLL4tOKjPj1eP15qhANJeo/
         ZGrBrD4k3v/oawbvD0bwOf14ifbDjePWGQhJHym87Xzk/aj5wMBBEkriT4hRePwLUJh1
         bm6wj3DlNnde5N6csLV95O3z126fFg37zf4EggkN3VH1Lq6ZZ0kElrHEOGFc0O83FLDU
         Yfrg==
X-Forwarded-Encrypted: i=2; AJvYcCVQmk30gb1R9nKV1hyn7v+hwonSk5yS8HMHPPlzjJZNO9Dg/ls//+U5kz2ytaEHhQeKdem7dQ==@lfdr.de
X-Gm-Message-State: AOJu0YzCbVGUwd3wA3cohYRb1HFCjf2k5gOwAJIT0It8+Evt2rTbTdSz
	9FKQwRaQ/ai2lkMjenO01UcT+B4cxfWdcsPNQC7L/ZVZcqeeoyIMer20
X-Google-Smtp-Source: AGHT+IHyXCOU2VlskpnXJTn38RErZEWjo8UlaTxIUZh1IZ76rkSrekmxj/BfRQhQN2bfIzNljm4YVQ==
X-Received: by 2002:a05:6808:528e:b0:44d:bdeb:f577 with SMTP id 5614622812f47-4536e52e5d1mr4850090b6e.31.1764939462481;
        Fri, 05 Dec 2025 04:57:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZAIFpftPQHCoy1cRSyaBsprpaA+nWFPSgW10LIZA2crQ=="
Received: by 2002:a05:6871:81d3:20b0:3ec:5edf:7cfc with SMTP id
 586e51a60fabf-3f508ff5903ls753196fac.1.-pod-prod-04-us; Fri, 05 Dec 2025
 04:57:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVmNgxv7Kt0Nqx9nbxIXYcmPHO6aqPI/kLWNHuj+lYmZR03q0zcwJTcw6AN+/EhaoDGDCPX3/ZFcu4=@googlegroups.com
X-Received: by 2002:a05:6871:b1e:b0:3e9:35d4:213f with SMTP id 586e51a60fabf-3f16915a759mr5735323fac.10.1764939461571;
        Fri, 05 Dec 2025 04:57:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764939461; cv=none;
        d=google.com; s=arc-20240605;
        b=UnodPLXu18DtjvwqhOggduN48LrCJipfGvjeLzNDEBBLW7BD3njSDCH1fSBclmxy4m
         nL5mdvV8m0WIyBKaRDEMV1hkRprG+fxtFkW6hpvUaRQHU+f8oc2/xog5QH/qo3ytdAJY
         Fjjngos4VFSi+EHsfLSuQ103GOQvHViO4iW3yc6qHXdf3aVmfFIGtqhw56qTfY+6ZQUI
         yWpcis6kSCjfkjg5jN6eWIrFvjsL7a/ogbvLSn5VPgsxuApswkj6b9t1yeScBbsMFRSF
         M4gVPIu5fxbKLfEu1ocWFfVkOLdAUb1V7UCISNkCCEw7vlQ0oqnVp/N4f36DFfveAXh5
         lxow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bHMFmGN0oadjbgXe1sqHZFT+wgMNJVQ4LPoHUYfdTrw=;
        fh=+szKSCYGF71VR5LgGqiEA/mxWlzSKqZzD2oLJDjLmwg=;
        b=i/VHhhbR0uJly+2Q8RjiX5iVHT3duwgqg2Xw1UpWMSXAtx70ERY7Mu2o2kCXetJ2aY
         uWuGyY/MaQqHf2oQQRIgSY5q0kjlctaLSzOu33KC7id3MCXYIjttdWEQrAoYjTQAeaWm
         Yq/IP3tDLVFBLGopPM6gsfucb1zwQR8mBLBL0KJ6oog3zmx8x2vXxzyv4bqZJ9JIv39y
         atOzNWqgd8Ku57pQ+aXo0DbByLTqaTf7KONpwyjFS9A0DQ69NgAnQUsMikE2FIKo7gCB
         Aid4iEfgJau6CHSqjQ7g2XE0q2lP7/kKpMwNJiy/Uol7+yhHwFAod+EsFMOQjgbfzN9B
         +a8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JvuKEFum;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3f50b5d83dcsi125262fac.9.2025.12.05.04.57.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Dec 2025 04:57:41 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-454-zVsvedK7Ppqdvd4IfslGNw-1; Fri,
 05 Dec 2025 07:57:25 -0500
X-MC-Unique: zVsvedK7Ppqdvd4IfslGNw-1
X-Mimecast-MFC-AGG-ID: zVsvedK7Ppqdvd4IfslGNw_1764939443
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4505C18002C9;
	Fri,  5 Dec 2025 12:57:22 +0000 (UTC)
Received: from localhost (unknown [10.72.112.52])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6FB9719560BE;
	Fri,  5 Dec 2025 12:57:19 +0000 (UTC)
Date: Fri, 5 Dec 2025 20:57:14 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Heiko Carstens <hca@linux.ibm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, linux-mm@kvack.org,
	ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org,
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Mikhail Zaslonko <zaslonko@linux.ibm.com>
Subject: Re: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aTLWqo03FUqN3QKz@fedora>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
 <aTKGYzREbj/6Hwz6@fedora>
 <20251205110311.11813A10-hca@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20251205110311.11813A10-hca@linux.ibm.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=JvuKEFum;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 12/05/25 at 12:03pm, Heiko Carstens wrote:
> On Fri, Dec 05, 2025 at 03:14:43PM +0800, Baoquan He wrote:
> > On 12/04/25 at 05:38pm, Andrey Konovalov wrote:
> > > On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> w=
rote:
> > > I also wonder if we should keep this kasan=3Doff functionality
> > > conservative and limit it to x86 and arm64 (since these are the only
> > > two tested architectures).
> >=20
> > We may not need to do that. I tested on arm64 because it has sw_tags an=
d
> > hw_tags. And if x86_64 and arm64 works well with kasan=3Doff in generic
> > mode, it should be fine on other architectures. I am a little more
> > familiar with operations on x86/arm64 than others.  I can manage to get
> > power system to test kasan=3Doff in generic mode, if that is required.
> > From my side, I would like to see x86_64/arm64/s390/power to have
> > kasan=3Doff because RHEL support these architectures. I need consult pe=
ople
> > to make clear how to change in s390. Will post patch later or ask other
> > people to help do that.
>=20
> We are aware that s390 support is missing / does not work, and will
> provide something. I guess something based on this series would be
> good, or are you planning to send a new version anytime soon?

I will send v5 soon to address Andrey's concerns. That would be great if
you or any s390 expert can send patch based on v5. Thanks a lot.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
TLWqo03FUqN3QKz%40fedora.
