Return-Path: <kasan-dev+bncBCKPFB7SXUERBHFJXDDQMGQEHOIYS4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B2F05BD85FD
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Oct 2025 11:15:09 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-78e4e07aa39sf231625086d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Oct 2025 02:15:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760433308; cv=pass;
        d=google.com; s=arc-20240605;
        b=VR6tU9wEoFYPGnAkccw+iByyMxF1gZSpIOr2sGCbachsdoLyalLnFRu2UiUSQKcZUV
         FF1JS0SEgvoKPnafS2Hn0cyAAZxNcOQzXuJdQ1rdYau5+94VnP4DlyRYPoYrRhYiEsX3
         Al9YwfNN2dk8ivoDzkOSGDe3iS0Cq7kcnYIS7ugERybP7Qhe7opLRZ/l8k1YSeKjAraM
         zoCurORxxi7rRgeiiEC7tf1Jx5lLhPiqigtjoS4TzeO3XsSnZghwX7IClkRWl1l+UcQh
         BwL6lVadHcqLkUdjjqhVwf3nYfXqP8szIL4kCqBA2NLUcnDTwW7IRp0xr4fLwPADG0SQ
         +nRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=kNH9St7DeynMULmzHarsGM82XM3TwI6L6aqSzh5pUUQ=;
        fh=sPo7NSrRy7JQ//aXJhtgmnV2aAv2hz5N5Vgk2uulW6E=;
        b=hzWHg/gkhXfxO7myKLPb2pjP2OKDiFrrFHioVU8Q9YKk6kv1fC1qAHbCLsEOwZ4scQ
         MuAYX4h3pJ6wifLZ39WukyB0K4APgbCWmZOkrBRBIGtAByg0Lvu1iXFoXBXH+g0VZaLj
         Fxc0uIcvtI8Fk9ZUqPp8sFX9ZjzCQGVcGH43aYzmr7bBziEmXZpKICN2JeBbjMgn6JeE
         sCGF6r3lvePiBJGk+ogUxJ5UsF6a0MKNEp75gpV3/teaD/8B88TEix79zMBk/A9TVf9V
         7yTZCuqAnQCeRhp8h8dqniMfDwiKqEJRpW5YJY9XZyVQY17P146VC71WAvyQn6mQaC6g
         0J4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TZ79chb+;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760433308; x=1761038108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=kNH9St7DeynMULmzHarsGM82XM3TwI6L6aqSzh5pUUQ=;
        b=IZiddZeJfYi8w7W+SBYRGjfhMOMhPg3faGlpx+kGAx+E/CjvmU6CXZZM54R1UyDFjn
         ig7/DoYx0npJsriccRGXkdGmE/8TslBjFgo2Iew2uKVccrN8Zcc5/3EEfHGDL9D0Sprk
         6xclh23S1L1hF1JxZagerqh+WDMjB63JG52rDrGc/CZWTucSSIH5mQiqsVZFPtQGn0YG
         lVMFygoUuKW5C5Ih5eq4SP4Y5hC2WCQghHZMMD+CTvqZ3doVMn+IMZtdo3nv2asce/fN
         Q2hMzuLPYAe69vYY9i0tSeWLX+llDWS2RWe1xt0SZAbwO890mdxkorNc+p/wTx77ZZpC
         NehQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760433308; x=1761038108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=kNH9St7DeynMULmzHarsGM82XM3TwI6L6aqSzh5pUUQ=;
        b=e56fc31X1g3zsrvA6JYPezcNrwotMcZN5AhregiofPQwk23qdGDHOWlMuNFHROwYIm
         Yh0zIwTFwZi6iiq9D4r8jBR3+kVPX6iBO1xOLZDzFwQEuNnLNrhJq4ojCcoqp+IZjXXj
         HkgO9tF8jXoCdfnU8MhqEkHwDRz9VcFoaogO/M74AH5r9cVNh6s5Ou8yjyGKghEJj9Ok
         LySnjGI7SRWM043GcOd6cVXTkeTKlc7k78WQOez4v5zj33uGbJjvGe8r1z2DCJf5PKYK
         qdVpcK4W44pTkVfEpP1QrA7yJh2angjk/487Z+EnWXcofUthR87PQF1iRfVHLAE3pvl/
         skLA==
X-Forwarded-Encrypted: i=2; AJvYcCXyJwHrfrjSNBVMmZJEgIJlY13J/lfIvL+Lkx+2scVZe01zNAfRg5CZ3oLeCsZeQjV9OItelA==@lfdr.de
X-Gm-Message-State: AOJu0YwOSc+6x6PwDQVU/jGJsUkUTyDZrrsshaT5cYf3moq0XD+MuCaW
	EouxhhhiSnYv4w9gfM4VEibiC6wRmI9MwGRVnGfn6TxQH67WkoGLeEAD
X-Google-Smtp-Source: AGHT+IHHgbk5kwS8A6gWad7SsKz6ETusyJkUbOLyuDtTjehEYDlbnTXE1/kh7Pn6NWX4XOot09EnoA==
X-Received: by 2002:a05:622a:4d8f:b0:4d9:5ce:3749 with SMTP id d75a77b69052e-4e6ead75598mr330948911cf.72.1760433308276;
        Tue, 14 Oct 2025 02:15:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5vjBiJciub8tfvbBd0nFrcYdN0KyO9KVY8Yt5G0aT1/A=="
Received: by 2002:a05:622a:8345:b0:4b0:9935:4640 with SMTP id
 d75a77b69052e-4e6f8981296ls86409771cf.0.-pod-prod-09-us; Tue, 14 Oct 2025
 02:15:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8Xt7IBlSV2MfyVpjAu6fcsK/v2kZ1R1UwXNxDA7xF08jzWWmI6z0fafrbASm/qD9vg6fEt0pnujE=@googlegroups.com
X-Received: by 2002:ac8:5954:0:b0:4d9:186f:8503 with SMTP id d75a77b69052e-4e6ead7f357mr405249981cf.81.1760433307287;
        Tue, 14 Oct 2025 02:15:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760433307; cv=none;
        d=google.com; s=arc-20240605;
        b=IdO0OdupD5gAbGpECXaNi1pWDxD8nd3A2Ah2WjSnXdjYgXv3WVoH7aEx5eGBIJ28CV
         fQsyaBtrwiXgdaWj1mP4+319HD/g62PI6hQ1RQ44XC9kjW4KX8FBUltmNPoVY/OUdk3I
         oQ1+rtLOuFjJW8gcvOCIVv+6rItKJhEf6pgPXML4ZMpp29VZNBjO/KL3KLiZzTqO/5pa
         kAkXxeO7DJtzy1VhtOyOw95WXaw0lOml7VCRjIT88Ucfa7/84g4xBvnuTC9T9c80tRqq
         WOgYOmJebhBNY7LiViRd5Aza1KTdbZDRbU8lw+8Z/h7FhwQkuJS4CvyVoifjKwwn68Xw
         zmEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=84qLuulQEWfDvvAd6y1sTa13pyZb7pX9XGxQ88tYQoo=;
        fh=KGmBayvdFqIEbrfynPxKTy2S6yLZ48BnTFg/XQX+0wE=;
        b=kYVcHEE2Pz8IucxxP48YfN0dXue03TkxrTuzTJFIQwXmEZX1Cza1UwC2OJuNeFssWC
         72/4r6KtrNcDw8GPfSvW+kLNyDsRQtdSWXHY91jfHLg/fFLrLLSXeIZcAaQu+sRwTVnd
         3bkbWVbqSdHEFeWtOgz9QNA98v/dEt5FREF8nqdimoJCDrhFRJprrGiBzJOubEieR4T4
         l748iEe6QM++qzSxGRmy9XAGPlqCCyIfhUSlwmLTkmJNtzjhnfrmMwm4CXABYqsLSIBY
         tAWLtZWjbGLgrj3eWh8ctntGWZtW9yk/rPMP2w7212fu4jW9+04g2MjyC9y5GkH7893p
         0QBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TZ79chb+;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4e715050e5bsi1479231cf.1.2025.10.14.02.15.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Oct 2025 02:15:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-215-habP5WxuNy6IzIfoPvjpwQ-1; Tue,
 14 Oct 2025 05:15:03 -0400
X-MC-Unique: habP5WxuNy6IzIfoPvjpwQ-1
X-Mimecast-MFC-AGG-ID: habP5WxuNy6IzIfoPvjpwQ_1760433299
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 08D5B18002CD;
	Tue, 14 Oct 2025 09:14:59 +0000 (UTC)
Received: from localhost (unknown [10.72.112.12])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 8DCFA1800283;
	Tue, 14 Oct 2025 09:14:57 +0000 (UTC)
Date: Tue, 14 Oct 2025 17:14:53 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, glider@google.com,
	dvyukov@google.com, elver@google.com, linux-mm@kvack.org,
	vincenzo.frascino@arm.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org, sj@kernel.org,
	lorenzo.stoakes@oracle.com, christophe.leroy@csgroup.eu
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aO4UjVmGkYg5Nyf6@MiWiFi-R3L-srv>
References: <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
 <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
 <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
 <aMfWz4gwFNMx7x82@MiWiFi-R3L-srv>
 <CA+fCnZcWEuBerMeS4RCXQtged06MJhY=55KsYeJEOJn3K0psXQ@mail.gmail.com>
 <aNNY1AzfGua3Kk3S@MiWiFi-R3L-srv>
 <CACzwLxh10=H5LE0p86xKqfvObqq+6ZN5Cs0hJ9i1MKJHWnNx2w@mail.gmail.com>
 <aNTfPjS2buXMI46D@MiWiFi-R3L-srv>
 <CACzwLxiJ0pGur42Vigq=JnYecyZn-Z5BC3VcqxSUttT54kEusA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACzwLxiJ0pGur42Vigq=JnYecyZn-Z5BC3VcqxSUttT54kEusA@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TZ79chb+;
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

On 10/14/25 at 10:27am, Sabyrzhan Tasbolatov wrote:
> On Thu, Sep 25, 2025 at 11:21=E2=80=AFAM Baoquan He <bhe@redhat.com> wrot=
e:
> >
> > On 09/25/25 at 12:07am, Sabyrzhan Tasbolatov wrote:
> > > On Wed, Sep 24, 2025 at 5:35=E2=80=AFAM Baoquan He <bhe@redhat.com> w=
rote:
> > > >
> > > > On 09/23/25 at 07:49pm, Andrey Konovalov wrote:
> > > > > Since the Sabyrzhan's patches are already in mm-stable (and I ass=
ume
> > > > > will be merged during the next merge window), just rebase your ch=
anges
> > > > > on top.
> > > >
> > > > That's fine, I will rebase.
> > > >
> > > > >
> > > > > But also note that Sabyrzhan is planning to move out the
> > > > > kasan_enabled() checks into include/linux/kasan.h (which is a cle=
an-up
> > > > > I would have also asked you to do with the kasan=3Doff patches), =
so
> > > > > maybe you should sync up with him wrt these changes.
> > > >
> > > > Hi Sabyrzhan,
> > > >
> > > > What's your thought? You want to do the cleanup after my rebasing o=
n
> > > > your merged patches or you prefer to do it ahead of time? Please le=
t me
> > > > know so that I can adjust my posting accordingly. Thanks.
> > > >
> > >
> > > Hello,
> > >
> > > I can make all necessary changes only next week. Currently, traveling=
.
> > > I will send the fix-up patch Andrey has described somewhere next week=
.
> > > Please let me know if it's ok.
> >
> > Please take it easy, today is Thursday, I will wait for your clean up
> > patch next week and post. I can do some preparation work for rebasing o=
n
> > your merged patches. Thanks.
>=20
> Hello,
>=20
> Just heads up that I've already sent cleanup patches [1] and
> Andrew has merged them into mm-new tree.
> Hopefully, one week's delay wasn't a problem.

Thanks for telling. I planned to rebase on top of that and repost in
one week or two weeks. I am doing some patch back porting for RHEL.

>=20
> [1] https://lore.kernel.org/all/20251009155403.1379150-1-snovitoll@gmail.=
com/
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
O4UjVmGkYg5Nyf6%40MiWiFi-R3L-srv.
