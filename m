Return-Path: <kasan-dev+bncBCKPFB7SXUERBIOMT3DAMGQEBUWC6AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7285DB56FC0
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 07:37:39 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-7341cfed3ffsf8604197b3.3
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 22:37:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757914658; cv=pass;
        d=google.com; s=arc-20240605;
        b=kED5aioG4gbHKmv/b/tgJebbrIY3IF6DU7H74lIEvo6oxyKL2XIuNDusPYv9QsOaFK
         EsHjs8LPFzXXIVss7XTmGVgSnj66MzOpC5Rs5ofLX7+RDn+fXNBulj4MHau9fM7VC2MF
         OWRXNBGxK0kGapo6dzOO2Y/XO1zyURO/gE6Bpc3FKbTlHAp73uXbI2tv4xG+OVDrF7dJ
         Hc3iKr1Xr+G4T/pACE4PA2AH8X22qv6oRCuOVX7KNYKtbIfpm61gJeoH9Ttj3XBh05Cj
         cCDaiMqp4ByLQ3k6vdVo8SFPyvwwZou5JQN4/c+sl+TldVRxUabJJp8Smv7qlEMuN69W
         wDyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=brQ7Knb5kg894BAheU+nGEmUSJ4H6Gu46Tj2hsCuNQU=;
        fh=jGD4Ax/uAwexrtrIsU/Hu5RkgqJ432ogrbISN9eUA9I=;
        b=ZW20Y0tkH7t90hhRB6kRPFVC1Sh/EKXzIM1e2lmAh38zplc5CWs4wK8smpCkLhaxBY
         DryWIORDg4tdsSs1dKM6gw0qp6vxm+kn93io0XSmbWITIwdAbbufVt3qRkA7vUlBSJZA
         zGgHYl0iaFUW0XTE7ogYUT+QPnOjCwY46rHs2aGjmjC8Qd0AANw5UUpuXYWDv6WiVg7/
         +o9OmD6GA1oRjuU81EUWWBy2LtDJ/62Ls30SPn6iw7UVxRnM3eI8AYJOYyQ1SLwWHOT2
         cxJ6fHFV8GZZ05ell7EzFuPPUB8QmtRefv7AkoUlcnBqiXL8txjWERcqzOIR+qt85rUw
         bYzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eeIzYdiW;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757914658; x=1758519458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=brQ7Knb5kg894BAheU+nGEmUSJ4H6Gu46Tj2hsCuNQU=;
        b=Q3pXryfVoWWSDU9lMz6+v4oTFydMI1YV1Ah4KoKFQuLk7L+2Xq3u2ey/4+zW6ZjxkQ
         plPUMCXJ2DibBwKOzUqeTKPreGhxW1oysmMVXRusqAwjzIqGD/+5b5RewPc8vv3+VSrs
         sWcXBcI2vQmGiqLsnuyPLpMxdk1bdI40jHDCesrbEugyWTeHNiIJnE9I04tIglDHPnSD
         VxLX+L2ndoZc37H+oyuWm8Q2xloLIUPvz+9DBjK+K5Bhs+XjA4wHm/mwDK/AWoj35VY4
         3/16QzdR6vC2OLiDYfQp/gCSsrSSS7kCENGfFR0c/zG54aZUpYbAjACD9lR+9nKWVgX1
         4SsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757914658; x=1758519458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=brQ7Knb5kg894BAheU+nGEmUSJ4H6Gu46Tj2hsCuNQU=;
        b=uwZAmYCBv8prTXZ/vDn65G987JuIDXvESyyssYGqIMAYhIetYXLOz0WXINZhof3AUz
         iWsxiMFj11otQ6pMu4srb0PyuDBs6c3OEjMt7kSU76eSrBu8UtQwUGVn9c1knmjl6sgS
         16/epeIAieXQoCWoeuLhhYGYWdzsO+h78ecSnW5Aabo8b7SpJNegm1A1g49KMSTxf+JT
         q7I5S8z/6CkBklk4lEis/AB/WLQM3qUhuAq/9Csp0pPdD0oMXDZdBOmZapGjoFkH2iEU
         TOe/cP5zMjd86PFGjP05n30v/1s5LwXhb8ECjGkGfqojtuigoZFBsLyWwZvVjS0GNgfQ
         5Wbw==
X-Forwarded-Encrypted: i=2; AJvYcCWeeUDCX6kjtyK8PxCoPajNaNF0TxXbiYnesAAJFQBsNQw2BPdN/HtUdyvSXDXxYq8hVGDeMQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZc4QW9RGXqyLz+RpSx2AaesDvfu8syo9Y5arCe5NFsmxcaDsV
	s3U0+frWZrLuYPV2JFDqd+xohWLYgv56M8eyYywpgwLJGDs5oLbQTM68
X-Google-Smtp-Source: AGHT+IEic40mvVmiBTBCf7YdY4tXCpSpSxVVS3HBix9brVEZ2o8QTz/RfWXPNo9FeTScm2nvVk2Jag==
X-Received: by 2002:a05:690c:dc4:b0:71f:8db0:12a3 with SMTP id 00721157ae682-730625d7222mr105494867b3.1.1757914657779;
        Sun, 14 Sep 2025 22:37:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd74LQOO999d78rv6rIBxFrVNosXy4wySAHUjn+zX81tMg==
Received: by 2002:a05:690e:d4f:b0:5f3:b853:37bd with SMTP id
 956f58d0204a3-623fe7548e3ls2177605d50.2.-pod-prod-01-us; Sun, 14 Sep 2025
 22:37:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6gbBUxSXOBLJJOm2zPgqBJrQrSOQ2THF44mq4bdOIMsQ0joK49MWSCvPuaiT1taGe42AZkeYAPMA=@googlegroups.com
X-Received: by 2002:a05:690c:490a:b0:732:ac81:fe7e with SMTP id 00721157ae682-732ac8201fbmr45522247b3.46.1757914656562;
        Sun, 14 Sep 2025 22:37:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757914656; cv=none;
        d=google.com; s=arc-20240605;
        b=WtHdGnDuUNxSnTTfWy2IbiZ9vnbS4qmcb3Ahp8LmfvbY2ETcHjQuuTQTML2r5VtexZ
         rGHf+KYjrarpnaL/kA6G//4mX7xL+MnvD3VNpOKksmhxiSGFCPdKKBim344a6RwkbbGR
         GhmAWLC6fDAZKe0sIggwsJqY1mNr3mCVKmEIQa15GdpSQ0NmR4gVc6I77hIW/EcVEjRj
         loVJKKekRWUHGcu7//bf3I3rMf8uNEbuY8JDe8HOrrK/xCgFLfolzOwyOYqzPY9mAwT0
         8q6vf1AHdrlm15YfkEZFbQxnBp6GPfVk3UIzglfhNZrLyFr4YyAmT5qp/VZVhRiIpHo+
         qQTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=rR4nvuLB68PWeoEq6OrLbNMctFC5H6hheeaS39RYv7Q=;
        fh=IAh4iARTQvlTi43QQupOtzjQhDX6EK9lhdAQgacoyfI=;
        b=gIO7uVMWCf8B8w+purNDcNnJWtx39zT+azdG/xwzTP7wIdZju+ABmTyRlqcijNAvHt
         VLSBXGWzXplUWPxuQ3mIPDTdpIMmbAfwhFWOqvZ7NmNqNzxtzIZ5xstOtmzOMhkxOZHX
         yeSqwqyrxpKrajzXv2Z6JrYHZw4I7GGlN2A1mzZS0W5g9FuMN3uNfD+xSgF/119IuLPb
         zUEsZvLxuyZ1qL7rseE8gMVB35nlzmnZFb7GwUDWUXO5CL5umRlD4KXmuT65D8/nC6o+
         A6TrCXdYuZ1Gt/FzfeZXNvo7oTW8md5OO4kQ4DxR/5P4CNVmekp0R3Aj1dl/iKlgZWQt
         FNmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eeIzYdiW;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-72f790a79bcsi4184957b3.4.2025.09.14.22.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 Sep 2025 22:37:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-595-j2IEoyyDO9S2fP4RaYfzeA-1; Mon,
 15 Sep 2025 01:37:32 -0400
X-MC-Unique: j2IEoyyDO9S2fP4RaYfzeA-1
X-Mimecast-MFC-AGG-ID: j2IEoyyDO9S2fP4RaYfzeA_1757914650
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 52736195609F;
	Mon, 15 Sep 2025 05:37:30 +0000 (UTC)
Received: from localhost (unknown [10.72.112.195])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id CC8901800446;
	Mon, 15 Sep 2025 05:37:28 +0000 (UTC)
Date: Mon, 15 Sep 2025 13:37:24 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: glider@google.com, dvyukov@google.com, elver@google.com,
	linux-mm@kvack.org, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	sj@kernel.org, lorenzo.stoakes@oracle.com,
	christophe.leroy@csgroup.eu,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, snovitoll@gmail.com
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aMemFIM+T7PBrx1G@MiWiFi-R3L-srv>
References: <20250820053459.164825-1-bhe@redhat.com>
 <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
 <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
 <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
 <CA+fCnZf0z526E31AN_NUM-ioaGm+YF2kn02NwGU6-fmki-tkCg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZf0z526E31AN_NUM-ioaGm+YF2kn02NwGU6-fmki-tkCg@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=eeIzYdiW;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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

On 09/06/25 at 03:25pm, Andrey Konovalov wrote:
> On Fri, Sep 5, 2025 at 10:34=E2=80=AFPM Andrey Konovalov <andreyknvl@gmai=
l.com> wrote:
> >
> > Baoquan, I'd be in favor of implementing kasan.vmalloc=3Doff instead of
> > kasan=3Doff. This seems to both (almost) solve the RAM overhead problem
> > you're having (AFAIU) and also seems like a useful feature on its own
> > (similar to CONFIG_KASAN_VMALLOC=3Dn but via command-line). The patches
> > to support kasan.vmalloc=3Doff should also be orthogonal to the
> > Sabyrzhan's series.
> >
> > If you feel strongly that the ~1/8th RAM overhead (coming from the
> > physmap shadow and the slab redzones) is still unacceptable for your
> > use case (noting that the performance overhead (and the constant
> > silent detection of false-positive bugs) would still be there), I
> > think you can proceed with your series (unless someone else is
> > against).
>=20
> Hm, just realized that kasan.vmalloc=3Doff would probably break if
> CONFIG_VMAP_STACK is enabled: read-only shadow for vmalloc =3D>
> read-only shadow for stacks =3D> stack instrumentation will try writing
> into read-only shadow and crash.
>=20
> So I wonder if there's a way to avoid the lazy vmap freeing to deal
> with the RAM overhead.

That's a very key feature of vmalloc, lazy vmap freeing not only
integrate the virtual area freeing on one cpu at one time, but also
merge the areas and flush tlb at one time too. Please see
__purge_vmap_area_lazy() for the details. This can avoid performance
degradation when many vfree() are called.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
MemFIM%2BT7PBrx1G%40MiWiFi-R3L-srv.
