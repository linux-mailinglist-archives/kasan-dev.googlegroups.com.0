Return-Path: <kasan-dev+bncBCKPFB7SXUERBTF62PDAMGQEK4PTNWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 13097B9D936
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 08:21:24 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-78f28554393sf12163196d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 23:21:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758781261; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fkhu6cRSilr55gXv9jkXv5W7P653PjNpWS4sCUrdOAuE7GP9vGTj5gdfKFnwhEYj8q
         whshGdn7nJdBqbl272HSJOwqzyRUHWlknoqMpd5YdZ9OOH2apTl+HstVtvgYedpdXNQy
         2SXwV+ltVX8Q+hV0zMq/jpnGu90h6/MYPQdbBQ/f/HlngXRCI8XoaIixY0SshLaG21r2
         TFDnDjhXauCdj1aK1wLTzhFSRXP83dV0k4Cqw3ouB6MIJjY+bT/srtSS4Lm20rwiJHWY
         34XAaFlH0pOzGNFTHKF2H+aFEexFLJzInEGXoWjsqMuPJMoHGHHYn4lFo3JjbS995BTB
         p6wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=xJlyfYS+B0xLl7BvrHaPfwUqORR+w0QVROrf4WQVUyM=;
        fh=RT0CPFxL7ZJXX7G1Gt07I+aKtX0bmduFs3DZOCAlYg8=;
        b=EmQsa2U0V3OEeZMfRlaJaz6SdScRRPIsSOxD9SLwLYCGWywOlFxDIlTORbJLYYlyzx
         COYt7S8Y7ZyNkJZxeUAFC2YH1w/Q2lz33UvO0CGQWERekvEAqIv6zkTe6Gwd8bwTW9YN
         zLMHMb/nrvdm0jTyzTvEVWi+a6eOB2gx5fMDYJ/ONOJXAjjz0VShNDc/U5mVhB9AKdT6
         S3p5mcSi8SYa8qHMDCgOIHqaAXAoyBwJbo/SDsRRXTDLNNKIMSg2Adh5TyUeXLhHB+x1
         hMZA73QMycadjdVC4cvq4DjW0/PCpLtMykke5nTNieRHcIDjeqIpWQKa9eTPrr0N+R8u
         g8WA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IcscfQRV;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758781261; x=1759386061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=xJlyfYS+B0xLl7BvrHaPfwUqORR+w0QVROrf4WQVUyM=;
        b=O2c8peIBHO4yCrEFzA59zguNyCCCpQsXXPlrRoGV3KWzbdIFLIdpRpvgli8CI+bDbB
         8i9csF3Qv4vvETmoVv8w5BYPZ4KMf1VCyka66EzA4Ja+5LYu4G4lF+YK1RkJmBk/47Ri
         TKseee9w7JPkmMDwNdU/SwZBi0dkU1pnXLvw5O+5n6eieURqtoWkEti7hJWvGloi75dz
         ALo2yOyPxelplxKqGGPJGW15tQyvKlGnc27TWtCj9wkhgHOjkNoUFB/9WSkZYydAkKVY
         ZLIFnbYzc6oHcP+rpJOxISXzvDW9sYrLdAVd8nCh4d6ibkOwCAoegNGe2NvcE/QryQwf
         Lspw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758781261; x=1759386061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=xJlyfYS+B0xLl7BvrHaPfwUqORR+w0QVROrf4WQVUyM=;
        b=wYe6xBX22Ao9VjMLtaSlJKhXq5m4Fnzkyoq875bnSRw/oXC+fBkqJWPjIlRvqtOhKn
         c+pMKEIbs+6QWe6UKntgXCp9rVOj4x0zbpznj0sRhbOFAxqqplYQxrpJ/HEaiHPZlyjK
         v27OLrhdjgtZ5eVmfQH9kmf+MoZgGUAg2KdArL3qz1oXN9D+jnzynhtxe9GWMrSgNM5n
         ZFJn0ShtcjrwsaBOtavjAByyDkBwQmVEtNYzuk9J2++MSUDC+uVCAKvBN63M+G3mqI/I
         xV4wIsoxDcXEOzmR/SWwRz5kB47rd5UiK+rpjBVTcC42cl7MJa0dRZT7MpW3X+CH64RZ
         xvoA==
X-Forwarded-Encrypted: i=2; AJvYcCX818YbfblbqhohWhBoRQzHVpEXjV9qFTovEN+b/7dC0CVQL+uvwEjxWvpRbPm/h4Dwe412kQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx+msgm+G42jmKTmfv0jxc+kgGZfQTD7wjtDni1sbxz97D98JFZ
	WrWREUzjN9g0F3MJzLUyYIUBSThl+E5qpW2qt0UxOvW04203xqcmKZmy
X-Google-Smtp-Source: AGHT+IGYJMV3XK5mA5/4T+hUrTbQYz2H4YQll0v42h88Y2D5ZEefe2ISf2389M/rwO7oqONsAhEJ2w==
X-Received: by 2002:a05:6214:1301:b0:78f:6005:35ba with SMTP id 6a1803df08f44-7fc3ed8ca16mr39882056d6.34.1758781260393;
        Wed, 24 Sep 2025 23:21:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6+lvZKObe+IhNbCOjfZv10LCZMGmsRbndNtmsHsZc+fw=="
Received: by 2002:ad4:5589:0:b0:78e:136c:b6d8 with SMTP id 6a1803df08f44-7fd7f9730d2ls10670766d6.2.-pod-prod-07-us;
 Wed, 24 Sep 2025 23:20:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgGPH1zwkiPBge/re7mAogFbFYGqjexAxWwun0p/J64KjQi7TJYH7tQIfw/ej/Yd1yLkvdTZSDcNo=@googlegroups.com
X-Received: by 2002:a05:6122:220c:b0:549:f04a:6e9e with SMTP id 71dfb90a1353d-54bea34623emr1076080e0c.13.1758781259549;
        Wed, 24 Sep 2025 23:20:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758781259; cv=none;
        d=google.com; s=arc-20240605;
        b=ZaZlVUsXGlX8c/EXwfOB/igtiJAQdZ5/XnqNKHdVcSSoS/AJIqk7GL0dTIixVdZkpU
         qhahe440a8KcS/Z7XqIs3RoW3dZpKdwpoZ+juRzSKy84TJkLGlfNaWgMXJQvhFs/oGCC
         N7UWUn5Z+NEVopt04zf3eqUuUNd88MKBn05svFppZJsgACQ2tKyx1+bvdHIhy/UkPBPW
         eHw8jhwznqGF+pUwMCsmqs3wYLJ99egJ/KWqAiBEFvrlaDh41h48+zzyWVW+zhFTyosi
         RbmuGwnoU+hG3tlQVCco+jmpqCQHQPNAQkwHE+1c7qufuvmLkL0BdDul1YjL3waJCBWd
         vxaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=MWVGs+PYKtMTbMr9CAqyDAMYWhTG9d/QRFnGi6Yteos=;
        fh=KGmBayvdFqIEbrfynPxKTy2S6yLZ48BnTFg/XQX+0wE=;
        b=hlRHWFt6mdUXmCJ1k8vsz2JO/KjcQvinwlYcQeVNOzPs6jBN+Cm2HIROGWFpcR/BuN
         TRx1XpUEEvF8+rgR9xBMOBS/Td9aEIiB+dItjpy5JAQu/8a5gC4s2ZJrtettH7ohZzxt
         NFKEqgS/S5bDudPsEscTsXcorCvcbvbTr89I08CUeMra+kdjMCVDMIPvFd/dDq0K6m6l
         myKQ3Lq6m5ruhkOICfJxZgB/sqDgR+K89hex2Pex2+Owupn2xz5swrws1ICrM2ySnEmE
         KbV2SJV1nTMjK2mHEU5IIK5DyEGEwvvYReuNtYv3Y2ifhTMDctltfzZuGtWAIAexig/U
         FmbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IcscfQRV;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-916d36c168asi46750241.2.2025.09.24.23.20.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 23:20:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-222-x8b2H0wSP5im0fP7tXEa7Q-1; Thu,
 25 Sep 2025 02:20:55 -0400
X-MC-Unique: x8b2H0wSP5im0fP7tXEa7Q-1
X-Mimecast-MFC-AGG-ID: x8b2H0wSP5im0fP7tXEa7Q_1758781253
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id F1E711955F45;
	Thu, 25 Sep 2025 06:20:52 +0000 (UTC)
Received: from localhost (unknown [10.72.112.12])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E97CE19560B1;
	Thu, 25 Sep 2025 06:20:50 +0000 (UTC)
Date: Thu, 25 Sep 2025 14:20:46 +0800
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
Message-ID: <aNTfPjS2buXMI46D@MiWiFi-R3L-srv>
References: <20250820053459.164825-1-bhe@redhat.com>
 <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
 <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
 <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
 <aMfWz4gwFNMx7x82@MiWiFi-R3L-srv>
 <CA+fCnZcWEuBerMeS4RCXQtged06MJhY=55KsYeJEOJn3K0psXQ@mail.gmail.com>
 <aNNY1AzfGua3Kk3S@MiWiFi-R3L-srv>
 <CACzwLxh10=H5LE0p86xKqfvObqq+6ZN5Cs0hJ9i1MKJHWnNx2w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACzwLxh10=H5LE0p86xKqfvObqq+6ZN5Cs0hJ9i1MKJHWnNx2w@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IcscfQRV;
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

On 09/25/25 at 12:07am, Sabyrzhan Tasbolatov wrote:
> On Wed, Sep 24, 2025 at 5:35=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote=
:
> >
> > On 09/23/25 at 07:49pm, Andrey Konovalov wrote:
> > > Since the Sabyrzhan's patches are already in mm-stable (and I assume
> > > will be merged during the next merge window), just rebase your change=
s
> > > on top.
> >
> > That's fine, I will rebase.
> >
> > >
> > > But also note that Sabyrzhan is planning to move out the
> > > kasan_enabled() checks into include/linux/kasan.h (which is a clean-u=
p
> > > I would have also asked you to do with the kasan=3Doff patches), so
> > > maybe you should sync up with him wrt these changes.
> >
> > Hi Sabyrzhan,
> >
> > What's your thought? You want to do the cleanup after my rebasing on
> > your merged patches or you prefer to do it ahead of time? Please let me
> > know so that I can adjust my posting accordingly. Thanks.
> >
>=20
> Hello,
>=20
> I can make all necessary changes only next week. Currently, traveling.
> I will send the fix-up patch Andrey has described somewhere next week.
> Please let me know if it's ok.

Please take it easy, today is Thursday, I will wait for your clean up
patch next week and post. I can do some preparation work for rebasing on
your merged patches. Thanks.

>=20
> > Thanks
> > Baoquan
> >
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
NTfPjS2buXMI46D%40MiWiFi-R3L-srv.
