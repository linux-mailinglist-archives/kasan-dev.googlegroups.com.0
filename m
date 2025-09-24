Return-Path: <kasan-dev+bncBCKPFB7SXUERBYVRZXDAMGQECBGMSGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id AD2AFB9813A
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:35:16 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-32edda89a37sf6043803a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:35:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758681315; cv=pass;
        d=google.com; s=arc-20240605;
        b=T/ka5Sf19acxN4KT37j2DoPsF/YvwL/0aU/cayhZQTMhHTiUHdwI11jkEj+NnHA0t/
         ffQin5tRZ5IGDtkGKpbRAxCQupeS0PpxHzw4Iu91vDwypLyLuVoKEPmxgHik+TkewsUf
         7DVkPscrpy7SBvSTB60IBID/q8PcZnIW/VPNgReGLxb3s9cD7libQz4FbuVSeZVsQldt
         eUBkWwS0fPo1XNqQ4gsd6dAxIPpUyMHrTdLgC7GkkxDFdVDPueRo9bPCf6AfqoPUPR4S
         jkxj6K5i9c5F9LrhtjTm9Cmi9EObzPWTUg3OcKZcDluxdAzz6EpfutMfrhimPlrhDy6O
         CKAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=f7Aryl5qk3kbf5QE6o8uPlazEu0R+5+G3RVOdbsk+Qk=;
        fh=TqOrcDvw+e3DosN9PHOHrTBjHyWpHYsG+nfTK8pIbZM=;
        b=Gj4Nj+eoZqMmiWa+ozaniLik/ghZb2XiF7aeNvQGsF5Ow7REBKMtte6MC10Fdmbel/
         Yz0iOIhSyYoD+Gn1wr4poUZzDEKXhxPKa7qW+/qkHgGWScpjyklFgRnwMJpT+/bQ6z/E
         8OB1+OY81PeY0pGvQk2tpz0GAcb93ToHn3EBv2vQ3i0fvLLS8GfyMUqlWPdUFMho32AT
         z1bAHEki46kioUYjYhkrvdmX0i9vFE7qwyXxxo7b3wWB+6bSeaNASFyQ22+1DNkpLM4N
         qfGxpn6LwCmxEAhxdtzWZMHRvVv6WRSHNJtmjO3B2oEQzar+gLrZtcQUnBKObpqEK76O
         /+aA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZP+sWQyh;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758681315; x=1759286115; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=f7Aryl5qk3kbf5QE6o8uPlazEu0R+5+G3RVOdbsk+Qk=;
        b=sM9VgSDD3wI/HUkFFPvJND1ehy1qDLp0nYjcmaY3BjtgD/j+xqm0VF3WEFkSKnrAaY
         bKhZM7n+4PUf/iqMwdPoJR95l6EI5Q4EpVSTsm5RZrEZuXicToiCiG35hCRnmbBTWEaE
         6orDhEBpgG0X6IPiAmvofYWyrlkuEBkbrdJf2wUzfF2snpGHBonYZedEWadK8qAOm7z7
         YVlTBA+Ga+4+a+UNg42+TssP2skX1rLhA4qnxN7DIGaFY8CGtjrG1iakzMF2hAa2MC6N
         37zeJApEmawf9vRfSaJ3dL7mUh/44ejdOR59GfgJ2/TOaveFAT/LuB8F/PZexzw2JE2Y
         8fhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758681315; x=1759286115;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=f7Aryl5qk3kbf5QE6o8uPlazEu0R+5+G3RVOdbsk+Qk=;
        b=jFAS7YwaH+9WzkhwfDuW3pKUJZZ1zBKRLmL7b1lejGaVGBhoVPBb9VBBe00je2KSiT
         k/wxqOZqJHf/wkvrodwxx50QWXYz4XGm83OlO9qOQ54629aY/8bgkHM1l4SCMypKwbjW
         WxnphuDedbQb2iwwMAvWsnI2xBE6otkkB7loBzQ9LG+Z722pYDKszleoeKX6ji9rUqNw
         Cvg66Jlw84WpBHLWr529oLX0TYZLcnMpEmZ9qwNufmmV6WijwRF2q/j6lkErov6NDQ8w
         eZwwra95jRaoEz+2EhFC4cr3Q5Pnru5DqX2mfsvo7yo5yN/7oaUxvvSNku6k2+BoUS9m
         WDZQ==
X-Forwarded-Encrypted: i=2; AJvYcCWaXtBhFjkQmWqg/OD54TdT7ANXmcRw4ExG42D/HTFEtMz28ZUFJ7TW4MWai/zI6Yd+tn379Q==@lfdr.de
X-Gm-Message-State: AOJu0YxIsN8pwoxi2ql5UmM/bF1KAML8OR0YtQyhGiIyw/TNlHyZViEY
	APpT9Qa9VBWccWAZxjHoxsZgHmqyI1JEde1Qi2UNOam5n/QXATU1RB6P
X-Google-Smtp-Source: AGHT+IGcmPxC9RQEyzD4+o/oDhVg7UIjSJ/Zd4rhPQAZgKy4sKQReFnV7iwDiBf0bR3A4j7T5eHvcw==
X-Received: by 2002:a17:90b:3d81:b0:32d:d714:b3eb with SMTP id 98e67ed59e1d1-332a92c9a5bmr5191064a91.4.1758681314617;
        Tue, 23 Sep 2025 19:35:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5VKm3SYPzdk042asOMEG01gmSDU6b/9d3r/hGH6nkPZQ==
Received: by 2002:a17:90a:ec86:b0:32e:43aa:41e2 with SMTP id
 98e67ed59e1d1-33065025734ls5239391a91.0.-pod-prod-02-us; Tue, 23 Sep 2025
 19:35:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUkNePxf+udyPe625KYpjsmuozi8poa1gnK30CZDg0cL0b7NfosUUwMJJwEbtLwPBKwMu21kO8a/yo=@googlegroups.com
X-Received: by 2002:a17:90a:e7ca:b0:330:8c87:8668 with SMTP id 98e67ed59e1d1-332a9513658mr5291573a91.14.1758681313118;
        Tue, 23 Sep 2025 19:35:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758681313; cv=none;
        d=google.com; s=arc-20240605;
        b=DtNwD5Dcy82NAsaC2RxFrOUnx3apj6zP6JlbcJsKnjuRxIiSCFbGSnaYouH3GZP3tX
         G93yvMPY/xRmnyW0b6mY47WvhYMhPywRFowIwjniTEmDe6mUrLtjc534WJSpXh/vPahR
         zttDa0VogioCDWud6QkS4Lx7nKc4FId/1haCQ/QQXT48XdBp7C+ARCXh+h24dByVJZJR
         GD8TdH1xzGnjDgxk05TwN6POVp8dapLZmGA7VRGdPVYc/4gtN46ruQ4yhR41po1W/11V
         ponIdz+PdmJVPHvtpFPXF9VYaI8MBvUtFDpv/xwMwPC/zFTXZuYu6rqFwciDbBKHBYlq
         JPUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=r8pUVu7ebrm0X4wJheoYfCWuw4PuHNLvghKI3Pai2MA=;
        fh=Sh3fEMrJhrd8UfKuoa3qD+1lFAoaYjDPpSyXWyymhkc=;
        b=ETbKHukA+AjqUccrkNIh0AP5LM5qIv3wVX/9j5FpTzdx7oBLIu1poue9DmYqwNRnK6
         zTrlzNFv4R8YdvnuGzRu7vyg/2fy7kxjyDRPHmH9kZ5nmPPFXGcjLJoZbXOEXAJW6Mre
         nGoZGzg/ACUn523ldqUqNclSuNEmaRrApODg9FQ4Gc1L4EUvOFqZdiwSW8IlyREiCUIL
         Yp9ExYMEYTyCLDn2S6tLujfLVXuWuuUBnNeudu93rTAvDcnk2VQfG0fu4jPzwc/sqsWy
         daO8uyyDPOmEmvU5S6dAkM73wvJ+6RpdwkvYuxgnpLfV6OdFSirU7lOUDeKp6pAmH8l0
         InIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZP+sWQyh;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3341aaaf219si51494a91.1.2025.09.23.19.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Sep 2025 19:35:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-215-MVxsJoxEMu6l8sCFbwGk7g-1; Tue,
 23 Sep 2025 22:35:09 -0400
X-MC-Unique: MVxsJoxEMu6l8sCFbwGk7g-1
X-Mimecast-MFC-AGG-ID: MVxsJoxEMu6l8sCFbwGk7g_1758681307
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 006D61956096;
	Wed, 24 Sep 2025 02:35:07 +0000 (UTC)
Received: from localhost (unknown [10.72.112.54])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 06F6B1800446;
	Wed, 24 Sep 2025 02:35:04 +0000 (UTC)
Date: Wed, 24 Sep 2025 10:35:00 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, snovitoll@gmail.com
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, glider@google.com,
	dvyukov@google.com, elver@google.com, linux-mm@kvack.org,
	vincenzo.frascino@arm.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org, sj@kernel.org,
	lorenzo.stoakes@oracle.com, christophe.leroy@csgroup.eu
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aNNY1AzfGua3Kk3S@MiWiFi-R3L-srv>
References: <20250820053459.164825-1-bhe@redhat.com>
 <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
 <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
 <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
 <aMfWz4gwFNMx7x82@MiWiFi-R3L-srv>
 <CA+fCnZcWEuBerMeS4RCXQtged06MJhY=55KsYeJEOJn3K0psXQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcWEuBerMeS4RCXQtged06MJhY=55KsYeJEOJn3K0psXQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZP+sWQyh;
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

On 09/23/25 at 07:49pm, Andrey Konovalov wrote:
> On Mon, Sep 15, 2025 at 11:05=E2=80=AFAM Baoquan He <bhe@redhat.com> wrot=
e:
> >
> > > If you feel strongly that the ~1/8th RAM overhead (coming from the
> > > physmap shadow and the slab redzones) is still unacceptable for your
> > > use case (noting that the performance overhead (and the constant
> > > silent detection of false-positive bugs) would still be there), I
> > > think you can proceed with your series (unless someone else is
> > > against).
> >
> > Yeah, that would be great if we can also avoid any not needed memory
> > consumption for kdump.
>=20
> Ack. Let's add support for kasan=3Doff then.

Thanks.
>=20
> But please describe it in detail in the KASAN documentation.

Will do in next round.

>=20
> [...]
>=20
> > When I made patch and posted, I didn't see Sabyrzhan's patches because =
I
> > usually don't go through mm mailing list. If I saw his patch earlier, I
> > would have suggested him to solve this at the same time.
> >
> > About Sabyrzhan's patch sereis, I have picked up part of his patches an=
d
> > credit the author to Sabyrzhan in below patchset.
> >
> > [PATCH 0/4] mm/kasan: remove kasan_arch_is_ready()
> > https://lore.kernel.org/all/20250812130933.71593-1-bhe@redhat.com/T/#u
> >
> > About reposting of this series, do you think which one is preferred:
> >
> > 1) Firstly merge Sabyrzhan's patch series, I reverted them and apply fo=
r
> >    my patchset.
> >
> > 2) Credit the author of patch 1,2,3 of this patch series to Sabyrzhan
> >    too as below, because Sabyrzhan do the unification of the static key=
s
> >    usage and the KASAN initialization calls earlier:
>=20
> Since the Sabyrzhan's patches are already in mm-stable (and I assume
> will be merged during the next merge window), just rebase your changes
> on top.

That's fine, I will rebase.

>=20
> But also note that Sabyrzhan is planning to move out the
> kasan_enabled() checks into include/linux/kasan.h (which is a clean-up
> I would have also asked you to do with the kasan=3Doff patches), so
> maybe you should sync up with him wrt these changes.

Hi Sabyrzhan,

What's your thought? You want to do the cleanup after my rebasing on
your merged patches or you prefer to do it ahead of time? Please let me
know so that I can adjust my posting accordingly. Thanks.

Thanks
Baoquan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
NNY1AzfGua3Kk3S%40MiWiFi-R3L-srv.
