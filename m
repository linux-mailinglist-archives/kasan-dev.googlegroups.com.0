Return-Path: <kasan-dev+bncBCKPFB7SXUERBAF63DCAMGQERFC3CWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A4A2B1ECB7
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 18:00:03 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30c347fce27sf928613fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 09:00:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754668801; cv=pass;
        d=google.com; s=arc-20240605;
        b=fBIMwQJb1YxOJ2qutjw4Al7+hnOo2LJIgUT143qQH/OmL85Xdsdx/EVTiRYvuXkyIP
         Q+hjFV4vqwxQYZCcjDvglYJ/wljH4kBg0M9p9NtOfy308qK2lLVQ6ANPPnbr3QRl07/J
         MuATEIODbgesj19Nx2fLBrW6GMzkbjiI1QghmG4JERVOIXODgRQXzMQVzRAvUI2DEvDK
         4pUBr32sl9aRpRXTLCJr/GYH3N9hdw1XpfMRkJ5KCOz/fkBr9AyVI2PnQMILk0f9uR6L
         MCqHQ5lkZbpSh2aid0opp+A2L17sm7e1hOmVFDFeNspLf7CWlr9qDD8yv6NDwlJKEDOE
         Ehgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=hkOFvwhKTiWjTvOldT60OQ8XW1a8ywbp7S+PwR4rr1s=;
        fh=TMEZt+RZu+IS4ODyTk+rIzJ++5DjJYPUSrCcyrpVXIk=;
        b=Rs0gdWLtkDLDzHFFxSxnMbvbV7c7Rpugul2nnfRAGqChZ4ZYLlFZnPylVTWPe+5s9l
         zKDkVl11aMCi++IAQl9H4ukjrvILBfp/4Iostf/VEYAjaQmvwQM+VIF4qqU8A0DUfYB8
         iOUmN4G9jJ0g0nsLNvJIwNp0TQ2/n/k57Nv9FkVpxT2aw2LkYWZsLaVjB/b4dPK+aNAk
         wgosa1k7BP1Kg1XKZgadP/RtW8Es69kZms71db0dBQjQNcYxkEvIIhUClV9psNF20ILh
         8i+ToWM+Ubv7nu7HL6igj3+fQnrVruNTaf0i9szt8YSOVjfqS3EKSCS4q7814MPzylCk
         TK4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QCkkV5S4;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754668801; x=1755273601; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=hkOFvwhKTiWjTvOldT60OQ8XW1a8ywbp7S+PwR4rr1s=;
        b=juXV2a4P/oGhX7tsnH7jlk4NcC2m0OgLzHcb0f4QtsNRtYd9r1y/uzGJ083Ogf4gAR
         lVWxpMvv8R+tZ/QTbtv2scjlte1WVR6MDM4ZTUdwKOMJ/1Q37AVXz6ziPjibcWJnqMYN
         yECHLBujR+rRNBBHvgb4B3HrhOa8uoA6olS0L7KrTB6geu9HAGBh2zR+kBsRqBgnv2K2
         gP0FjkYP5sCKxpzY0N98//E7bsX1D1zBTlvZ67ye8KNlP1E/8UAElG7lHHiBzyE7EEGc
         uSpAWvJAJw6hqUkS4MS2Pr7VDM4wJZZK84Wc1KdpvM9uDc1Ity7OI3aj8j6bXwIFheDv
         zDWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754668801; x=1755273601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=hkOFvwhKTiWjTvOldT60OQ8XW1a8ywbp7S+PwR4rr1s=;
        b=mfVyfEsEi4HmZ/dTn8adute7Md8uIFkI5PW7B5JZwnNu+IE2vCUZy0/K0ciDPOBzh4
         gGRZQeK6tQ5gB3iCvPZ/76TTPp4r44WyMkdLercUTjI2AVlv7OFoG5OGf/f+/39hpiBb
         njAHiACq500U4fe9DyPX28y+p6dOMnvbEj6o7ao5/F6H/XQLCXjG0S6io97X4l7O/FG/
         fTFGPKNCj39dFQRJbkZoXYFrzarccldgV3gQq0h2Ks7LIO0tkaFufeGt78mw9u0CSHZH
         KGx6rCXDlXCILmcWpM9bk3Oqd02OmmS3E1wxBngyXT/x7pLjinMXIPzO462VbACYomX9
         PhzA==
X-Forwarded-Encrypted: i=2; AJvYcCWeCxxnUJR8OPtkCEGTIgJtq8jHe6qIlrRSw0D8WPE1OPZIPYDQGgNrQRirAfgspgmFRy2VEQ==@lfdr.de
X-Gm-Message-State: AOJu0YzCN/0wZNGPjjepCqIb8x9e2WKsWcnyR08+X7U/Km5aR+fLhoxG
	OogJaEXA2vxsIjQscTCkwYuj+KSwhcCAFXKeXbTgm/Hv5A2izhdNg1TT
X-Google-Smtp-Source: AGHT+IHnVd5Gmdoh91TFZ75fASqQi7TXwIAGv69jgfUD7+X2lVy27rIR8y6aD2eApg55PFVFwE3/XA==
X-Received: by 2002:a05:6870:64ac:b0:2bc:7e72:2110 with SMTP id 586e51a60fabf-30c21102aa3mr2185514fac.13.1754668801109;
        Fri, 08 Aug 2025 09:00:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe+JSR5fENUE4znzaVEDD7gtSQIdTj88PrjQMR7BcoMOg==
Received: by 2002:a05:6870:58:b0:2c2:2ed7:fb78 with SMTP id
 586e51a60fabf-30bfe37d105ls710780fac.0.-pod-prod-01-us; Fri, 08 Aug 2025
 08:59:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFDPqcXqBMkriDoR4UUzltVexRbFuKS/xNNa0hN6rfrxFPoA2RB3y6EItoz75tOZRTBdbfNNLTVrE=@googlegroups.com
X-Received: by 2002:a05:6870:c4b:b0:30b:a20a:8799 with SMTP id 586e51a60fabf-30c213319eemr2424496fac.27.1754668798183;
        Fri, 08 Aug 2025 08:59:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754668798; cv=none;
        d=google.com; s=arc-20240605;
        b=LVxmPL8GFW0Z+vlvcNKM/dkbu9lUuJuiICsbndqMIxfVXp5RbrFMTPD9Ff4leLn3uy
         kJ+uFKi85c39dxkpR74MWg5W78WkxAJrpnzbFQmjAoG8vg9JJaPoOraqAaJtIm3Grn37
         WPNc+k22wabaEYuaJN0Uusbbz23tF2Mrfv9toeYCNmgP/WyyJuVNNeYUrN66P0VHNcLW
         Y4+7DIwg+ML6eknuPaMC+qxQtZIYOkl//mBfVO7owo7RI4vt17lDjqZJK6NZb+pWU0nW
         N9k1apAumBxr+BoHU2l3/vsoQJaEaTrzSaHUnhdX3uozPff6vZqNI0diTcRmOGHinYeY
         ke9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=YGK9n6dq7VxCb/OM51wQ3RDMD15RnRtHlU5OclWuDJs=;
        fh=IeZ3cIZwPqyvuITMeuQ8G+Pxg9m9IXoSF17VNZxDIjM=;
        b=gRxenjRNKwcnlaIAk8SKj6YwGketF26VdtnRIYZ7ml1ZfhD1iGilQPhFXMlO2fnZ4f
         HR0uxoYPKq8qX67S0EpOtQfbh1Z/DIJ2KP8a9P+djoavYeIOdNOuy4AviUzfqypqBibK
         5mmGJoOuyLQ96mIQrRSb/4jLeaQHCuSGiyQhZv58PtVFSWEWn73O11gtQViRpPltnBys
         Xpjape3Lx8tx6MhqUuISimL5gS7/3F2LD60L71MtW/IpUomdN2qbpOsU1SnXRRkEyaBh
         2Hrxc74bErsz3yS08gP9mNr2XPnv+cuoFFZjuXfl4/icgEWnlhjNTiK2SmHz3mL4kinQ
         porA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QCkkV5S4;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74186e002c8si1005882a34.4.2025.08.08.08.59.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 08:59:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-203-wt4H8Zk0P262tjW9FjN_lw-1; Fri,
 08 Aug 2025 11:59:56 -0400
X-MC-Unique: wt4H8Zk0P262tjW9FjN_lw-1
X-Mimecast-MFC-AGG-ID: wt4H8Zk0P262tjW9FjN_lw_1754668794
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E6256195608B;
	Fri,  8 Aug 2025 15:59:53 +0000 (UTC)
Received: from localhost (unknown [10.72.112.126])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 54FE0300145A;
	Fri,  8 Aug 2025 15:59:51 +0000 (UTC)
Date: Fri, 8 Aug 2025 23:59:46 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all
 three modes
Message-ID: <aJYe8rAa3lIe4Nat@MiWiFi-R3L-srv>
References: <20250805062333.121553-1-bhe@redhat.com>
 <20250805062333.121553-5-bhe@redhat.com>
 <CACzwLxivXFYXuF1OkqcP9THar7UGQ3VVAQgQm=PU9Tohb8hnRQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACzwLxivXFYXuF1OkqcP9THar7UGQ3VVAQgQm=PU9Tohb8hnRQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QCkkV5S4;
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

On 08/06/25 at 11:24pm, Sabyrzhan Tasbolatov wrote:
> On Tue, Aug 5, 2025 at 11:34=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote=
:
> >
> > Now everything is ready, set kasan=3Doff can disable kasan for all
> > three modes.
> >
>=20
> Hello,
>=20
> I've been working on this already and a different approach
> with the Kconfig ARCH_DEFER_KASAN has been proposed.

Thanks for telling, I don't always watch MM mailing list, so missed your
earlier posting.=20

I went through your v5 series, we are doing different work. I am adding
kasan=3Don|off to generic/sw_tags, and have added kasan_enabled() to needed
places. In fact, based on this patchset, we can remove
kasan_arch_is_ready() more easily since in all places kasan_enabled() has
been added there. Before seeing your patches, this is what I planned to
do to remove kasan_arch_is_ready(). I will see what can be done better.
Maybe I can carry your patch in v2. I will try tomorrow.

>=20
> Please see v4 thread.
> https://lore.kernel.org/all/20250805142622.560992-1-snovitoll@gmail.com/
>=20
> It also covers the printing in a single KASAN codebase, instead of
> printing "KASAN intiilaized" in arch/* code.
> Also covers the enabling KASAN via kasan_enable() for all 3 modes.
>=20
> It's up to KASAN maintainers to choose either version.
> I just need the confirmation now if I should proceed with v5,
> or your version if it covers all arch and cases should be picked up.
>=20
> Thanks
>=20
> > Signed-off-by: Baoquan He <bhe@redhat.com>
> > ---
> >  include/linux/kasan-enabled.h | 11 +----------
> >  1 file changed, 1 insertion(+), 10 deletions(-)
> >
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enable=
d.h
> > index 32f2d19f599f..b5857e15ef14 100644
> > --- a/include/linux/kasan-enabled.h
> > +++ b/include/linux/kasan-enabled.h
> > @@ -8,30 +8,21 @@ extern bool kasan_arg_disabled;
> >
> >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > -
> >  static __always_inline bool kasan_enabled(void)
> >  {
> >         return static_branch_likely(&kasan_flag_enabled);
> >  }
> >
> > +#ifdef CONFIG_KASAN_HW_TAGS
> >  static inline bool kasan_hw_tags_enabled(void)
> >  {
> >         return kasan_enabled();
> >  }
> > -
> >  #else /* CONFIG_KASAN_HW_TAGS */
> > -
> > -static inline bool kasan_enabled(void)
> > -{
> > -       return IS_ENABLED(CONFIG_KASAN);
> > -}
> > -
> >  static inline bool kasan_hw_tags_enabled(void)
> >  {
> >         return false;
> >  }
> > -
> >  #endif /* CONFIG_KASAN_HW_TAGS */
> >
> >  #endif /* LINUX_KASAN_ENABLED_H */
> > --
> > 2.41.0
> >
> >
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
JYe8rAa3lIe4Nat%40MiWiFi-R3L-srv.
