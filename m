Return-Path: <kasan-dev+bncBCKPFB7SXUERB653VXFAMGQEZCAEWJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 930B5CDB429
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Dec 2025 04:29:01 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-88a2cff375bsf119994876d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Dec 2025 19:29:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766546940; cv=pass;
        d=google.com; s=arc-20240605;
        b=C8a7svJy75sShECD/eB1DTW4l0IcSfd5NIF0WoNaP1k0vVJ9IRdJfPxaJbNr5pk3m9
         NjmLR/x7j6DlqDXOUkhWZvgN3lb/B97vhD9SfZnOnH/NQM5vS0BKkbFp+szf5QJagY9u
         QD7mDv1XHL2OXuCiOgotl6ryBIY7ezzrb/cZy3eNNHxEpk7GugDLMSVaJxW52Pv6i+0T
         tP0+tLw5PYXyjq1bq0hZGCLrgEUqTd7OrZ8Mh+/4+Je6givZ2/3myBAgu3b/xZ1CrJ6z
         aTuWx5gTLbmwXG/aV/Amtyu5D9Q2vEY/EBI8zQKnx6yWwVvAsT9J8/eVe2Ei8RUNLvwO
         ra2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=a1PqzmuinuDklCuZ4CfnUKZVo7TrISRobH2be2UMyyQ=;
        fh=iJ1MtrYthASW0y5Oi+HJjgKoANh7GB15/bi2HzDQcKM=;
        b=VESJXVK1CSqE+hKqiIaR2RRc+OcNatsp6xbwCfarYYUpY6W+4F2q5/Ffc6kUm0LHTr
         G6TdHyLekVP4m3sp/b4WtXZx1mf6QEff/U7HcL1kmq00F+4QfXm1dpOh/L0HUboId76l
         mwX1gT3cRAPL1ibzsRQG7O57o5hCoA01eZZ0csvTQC6nz9n0YjqpLZGqVM9arfBP2G4T
         nS5RuBg6ORKoi8CDEM5k4KAZZjFoAssWEwAgWzI3/0yZwZYKi0P/ufbvm91OnOHizX/Z
         R6T9fDK2BCn4exm3D5t3K4n1T0AnOt6hBzy5g8MpPs2LH+nAEPOViAyp+znolkGhxDOW
         jOHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="N/wKxGjM";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766546940; x=1767151740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=a1PqzmuinuDklCuZ4CfnUKZVo7TrISRobH2be2UMyyQ=;
        b=DhoiL0Oa7TwHK6gvLPiiBBS6BSH/Ho/RdamxPm9y8d0AMOoR2l1zLTFnLSpMGAzLfH
         sb7rGcD3xx+3j87cf3XBw4fH2yO0HCIp5FtngBgeAPfTg2OLzgw6SMKxBhW2mB869Nz/
         mccXZLyyB2boHBmphGC+83ggzshlWwB23qW6BpysYTawobub/jvZVJOVwrxZVt3ZsBqy
         sr/TtDbUMJopHLkDXJvo/DlHgIVQVenMP2xjjqjaYpwF7/Z+5ysksOBiwbGFbh3tWu3V
         jUtfPDmKNv5ofW53BhhsVfzeVJk+px4g+vkvTwpuXFR0KHyFkuxEq83wNvzTt2Qw1/Tn
         K/ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766546940; x=1767151740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=a1PqzmuinuDklCuZ4CfnUKZVo7TrISRobH2be2UMyyQ=;
        b=w1iaEvhlXEKOs0j7RmgMC0oHnB88PcCx0cEGBCkN+jKonzxeEBqTmzVpZuy7x59e8D
         5iQ0Qv/9EdnaKcsjtPGSoQ62SpjPckGcIOAo9iPRezGS4QX/z1TgdqvZy/LMro215NzM
         lQPKujuApuCk/AMDggYLxFNEh1mTBxBdJ+JecRC6QI58RndDmnWFIBIkaTVawV9HUOkh
         Mit+XBGROydcGWM0ot1wjXJ+MVYq+TQKoaZaMDVqCJ3WA+OcO/LDwBLZinIWTIxjiHH+
         R6TArmFm9Vpfupuao5SX6Rsy9NmNPDwJtuuXIhLkxeCDnsHjC+bXsduamyaEuMfveGiP
         ZVGQ==
X-Forwarded-Encrypted: i=2; AJvYcCWjEiiTNaX0z9YkeyP9NY0DBGxxtgbpM8apNYyuKnnfji2VbcA8IzMkot34GeJEercHTaYlSw==@lfdr.de
X-Gm-Message-State: AOJu0Ywvz4BPwsymX2VomzPGC/6DQzCWni8RKw4VaWTM6+e8+z5OYn+m
	/SD9KSSqLdo0GytnuInyHy8FeD+7SdmsymPbWOffaiJw64O9MLYV8Kau
X-Google-Smtp-Source: AGHT+IHqaLb6CDlTfMUv00LNjS+/oL0RK3c1rda/0gqHY7ky+jJA5RiyCKnnjvYZYUu/HBozWPrxbQ==
X-Received: by 2002:a0c:ec11:0:b0:882:5e6e:b94e with SMTP id 6a1803df08f44-88d83795016mr185456966d6.45.1766546940151;
        Tue, 23 Dec 2025 19:29:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbIghSftgMWqvGc8SYy5ekPE19aCM5+KfO4ZFu6ORMGrA=="
Received: by 2002:a05:6214:230b:b0:880:803b:bd47 with SMTP id
 6a1803df08f44-88a525bca84ls138876646d6.1.-pod-prod-05-us; Tue, 23 Dec 2025
 19:28:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXEDIuIlX46J4V6EKcfxS/CoS0KSWI+HTSVzjag7pOeOu91FJLf4mnQe/LmEeDBmlo4Mh8zvEinsHM=@googlegroups.com
X-Received: by 2002:a05:6102:5086:b0:5d3:fecb:e4e8 with SMTP id ada2fe7eead31-5eb1a61eefemr5013175137.5.1766546939273;
        Tue, 23 Dec 2025 19:28:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766546939; cv=none;
        d=google.com; s=arc-20240605;
        b=JsZfIz6IVBkVomSCzO7jNDbb69WQfRiqH+nvT1oUnTiKRMQfeFxHWeYb/6gxoU6uQ/
         ZFIdb2ABBh9ZxW/e/El4RupF8DdReURpGH2x9MWnGuqbxqS1ZtwvkYgBAw1B5l76Yrg2
         8W4CtcNYfGJYMGjZxzWC7J7YKjeJaM+MBc++ylcUF8a7bM1A7cN9Ch2xxMhuww/9NRa7
         niKtTLWkbo4X0T8O44CF0sfdTMdQEkUx2jm60U9MbdJnfUlRkmzdg0NAmOX0ZhHP/L4C
         OUyIIfE0Mmr3t19R05isU9geNy9fh5pN9G/mn+womlmIHtQHoGxKhj1Lhtqh+EL5dHLa
         jFXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=PEnYiKFC1BPTOh2lEem5yt8CWGQxdCaNcVZbw2GCpAY=;
        fh=bMZBJix3YMSVI/m5jYA+cZd5+5N920UloQTCzaIamYQ=;
        b=loIR/krvW/z3pZxEmqaADDUJE5CPEWiJzOLJVCklOy7IScRRqFrzi+xQ10yokwHigy
         fDR2W0dJbx7WbY8mopfXPVVpn4+reGLDgPTIzOQYl4eAOc3E6TnER9SOFkx3lMki8LSN
         ttcfnT8C5EqhluH9R4kD8sxb+VpkyFX+Hj2NEUXHSs+lAqO/yT+UpMdwnfaW+/z0gdT+
         A5VWGiZb1uUtd5RKU121GOwhRYFYj89D1SD27+XZtQqqg5LCLHmYjvD5BiyoXt4RMBOd
         ddjhoKzp5LQj6TKYHX0oqAJM8ksXukq71UQiuowClDg/o2Z5E2NDswGin7Ok/mjvZEbA
         WhkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="N/wKxGjM";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5eb1a85b7e0si267461137.0.2025.12.23.19.28.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Dec 2025 19:28:59 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-130-69w2rVsPMJybW1GIqvYelA-1; Tue,
 23 Dec 2025 22:28:52 -0500
X-MC-Unique: 69w2rVsPMJybW1GIqvYelA-1
X-Mimecast-MFC-AGG-ID: 69w2rVsPMJybW1GIqvYelA_1766546930
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6ABDC1956046;
	Wed, 24 Dec 2025 03:28:49 +0000 (UTC)
Received: from localhost (unknown [10.72.112.137])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id C99551956053;
	Wed, 24 Dec 2025 03:28:46 +0000 (UTC)
Date: Wed, 24 Dec 2025 11:28:41 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	elver@google.com, sj@kernel.org, lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com, christophe.leroy@csgroup.eu
Subject: Re: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aUtd6es8UC0lNf/9@MiWiFi-R3L-srv>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="N/wKxGjM";
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

Hi Andrey,

On 12/04/25 at 05:38pm, Andrey Konovalov wrote:
> On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote=
:
> >
...snip...
> > Testing:
> > =3D=3D=3D=3D=3D=3D=3D=3D
> > - Testing on x86_64 and arm64 for generic mode passed when kasan=3Don o=
r
> >   kasan=3Doff.
> >
> > - Testing on arm64 with sw_tags mode passed when kasan=3Doff is set. Bu=
t
> >   when I tried to test sw_tags on arm64, the system bootup failed. It's
> >   not introduced by my patchset, the original code has the bug. I have
> >   reported it to upstream.
> >   - System is broken in KASAN sw_tags mode during bootup
> >     - https://lore.kernel.org/all/aSXKqJTkZPNskFop@MiWiFi-R3L-srv/T/#u
>=20
> This will hopefully be fixed soon, so you'll be able to test.

Do you have the patch link of the fix on sw_tags breakage?

I am organizing patches and testing them for reposting, but still see
the sw_tags breakage during boot on arm64 system. If you have the
pointer about the fix, I can grab the possible unmature code change to
make sw_tags mode work to finish my testing.

Thanks
Baoquan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Utd6es8UC0lNf/9%40MiWiFi-R3L-srv.
