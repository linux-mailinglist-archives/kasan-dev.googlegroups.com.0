Return-Path: <kasan-dev+bncBCKPFB7SXUERBMUC5XCAMGQE5XS7ERI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 29721B2285C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:27:16 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e92c0510438sf459698276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:27:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005235; cv=pass;
        d=google.com; s=arc-20240605;
        b=aBDWWDSXlikLbQgopQRxsbgx98TKZhgt2jQV+sKwZdnzVgA+aiytQbC41Oc7tGSW5i
         fIC7NxMrmGvqpTrcfUvskHtZlPHe23qIawSV6+GvSC/8DuJ8T1uy/1XO/XryhMlAEWea
         uakJgHclwkfCRsD8gsKIFQyVQ1GpMb+S6PNpmJ5Ige7FcYiylh1fkKQ4ZsGAP1tU9Bt0
         EnZV7ddRiSBe7WM5Z5V7La5ihsUeUOPsJR63MQ4UR27AzK1OjIlA3zPyIor+20l/n9Cx
         cc16HkIdgtvSEgOpNOvtpIB2odM7Sbm0geUmWmuo+jSoWXk4Ah8C3cpuwWELs37RVxj5
         l+vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LGKdxLvmcmClibXlAzzx4VIDJLfC6zWE6Ghyg3oekik=;
        fh=p8UDHUJV8r0z8T6pCBeXXMkuAyCZe1z5bKN4dGDlq3c=;
        b=iwlpMKFEaeXltaGAOlZjCm8JuyqtK7ljt33CUGDl1ta7NmfQ67mafmOBan7f22pJWB
         zIrR2+dGXiF0ICmJrYxNf4UzWDTaOjt83fWwJKBXUPa0g5Lhs3KX8o7rUEdcAvC4NW1R
         I2SNNj2dMjxVu1JH/BKJy4tdEnYSMzCNVsnpo7cugc9685CSds+CQDJNGBI3RPULSGNv
         Bi6BR6gFh9VPMdXXt4Zey/CqG/6tygcPEQ5raYOMeVcnW/38eniKfqeGUo+RD3eTo9SZ
         9dckKw08ysLyJU6bmTxAYRIx9GvjhHH2Vutz3pge0GxGhXlPjFQgAprljEjg5oXvXXnr
         PtKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HLF7+cJE;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005235; x=1755610035; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=LGKdxLvmcmClibXlAzzx4VIDJLfC6zWE6Ghyg3oekik=;
        b=XcJzYDLiNmgXnleYhXeMiv2oojf8Q3vZjgYU5lzELHgTESqjLbLYFXCJ3+p5xnaxjB
         BWjXtycSxhpzMd9UPGRrWFdEXFxRrq3+qBOx9nNz5zgYrovSKTIZKtiyGkIHt/dgaDCE
         PJ027dFG2FezNnqR8shbt1TsNERj1FN9YoHOEh6pd6BpO4hjXx6W4FFKPI3CQK4L1Y3T
         MuYzajfKelwpRGw7XqAzkARSHN/R01QWECdMHPTAjjNF42BRgee5m1a3i/PRKNUpATYs
         AlEtMsNj4bHFUMOiGqAGmiukp104V7UAAW5M6tx3j6ylilER66e91lTPPS0KMRErxXlz
         ub4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005235; x=1755610035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LGKdxLvmcmClibXlAzzx4VIDJLfC6zWE6Ghyg3oekik=;
        b=Jcd48stDvFpVw8MVRGv6ey06xyMyV7GMdYkHI0WsXthD1DydFJg1/+O4Q/DBjztFSt
         TXQE+HklfQNRCMJnhNburk/Bd+qv2/kbzx3SKFyCfRNVDy0T2GfW0RpbDaDbxj/rwjPn
         cI8bsxBJhILF3MwaeWXEq8uWZWvhqgB1QeUor/Zvw0MG5rDLRcM5WgqI5G54IsY7o4dH
         K8yKrhNJEI2ZWCZ9HfdwGJCAEgCEwoWADgDF/d6hPhQbUHZcrZLuj+W04BKCHGSc545d
         N2WVKoxHKZRocLEUKcZhc/PzKexVO/HtMK1WpQJuqPT0oK6yzr1LGXZVM8EgF9wrsAzZ
         MG0Q==
X-Forwarded-Encrypted: i=2; AJvYcCV0+0HzJJ+LqT8T2bwazdjwl1rdSaEpX4P9ZCB0B8G6YehfN9P4lJO4LPQxUT0e4A87nutqEQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz9awgh6trfd5rvVqImrJLYk0D4ZBn+V93lvHc1YzoHy+PID9S+
	gopc/xtKUHkeVsmLK8nd4Cdo42JuM8AmcaAHyj1//mb4LZQ9JXRQvSJC
X-Google-Smtp-Source: AGHT+IFj8WqRN7pnW005r5QJn/j9Lihsu6/i6+2qrhm9jPh5UXCLzmOnvJs9JcrPPpbTKw/OcIpwKw==
X-Received: by 2002:a05:6902:70c:b0:e90:582f:33b9 with SMTP id 3f1490d57ef6-e90582f3c26mr15370214276.26.1755005234893;
        Tue, 12 Aug 2025 06:27:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcvUn+uC+ZWtKj5fOh8wP5vI4AQtxVCE9lTFqOrMGazew==
Received: by 2002:a05:6902:4581:b0:e8f:d146:b078 with SMTP id
 3f1490d57ef6-e9038cdf613ls3726518276.1.-pod-prod-08-us; Tue, 12 Aug 2025
 06:27:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXL6MV15a1aMhTCsLUgFGrmqt0CAuc5nCmPwNG0v7shR22enQ+I37D3AQhqg6/eDRSlquBo3NPwf2A=@googlegroups.com
X-Received: by 2002:a05:6902:1205:b0:e90:6dd7:6c0b with SMTP id 3f1490d57ef6-e906dd7700bmr11720808276.29.1755005234082;
        Tue, 12 Aug 2025 06:27:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005234; cv=none;
        d=google.com; s=arc-20240605;
        b=fwXYNAF5pXLQ0MIpUtB9zD1YiXYNBPPSW3MZMA6WRT6EuRYPcqYjQICTdNXivflCOn
         Go2KQ3wQBBle+/7JLDH33vAB32JwbSeWLSd1fuPgWmTMY0BnFbkQUerpwYK3OCun7cvM
         UCft4ewuKFaOBeW0guK7+YEu5HTpqQp5h7o9Zacrt62m3pBnd56yZtpYBYUxrbsWdlfO
         vuzpLem2tjwJAHpL5+q6dFaiQzikhmreu+aLYk2i/TyyCQXAtI3v9CT/BKS5lQ9r+2qf
         ZiIQWTMo5mi+OdchPV0XQnwJUQ5fmRJB/9ViiH22AhPrDNfTnu0m3zzrBqTnaAeXirgW
         Jrcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5ek84SNcPpQCmMHvcqQa3TlILZVgRFvPfl/s5BFwLTA=;
        fh=/3jG9ethQoAl5TnrFc52/QqBLrrsYAKqXTTehFKeI9Q=;
        b=graau8zSp6WudLjmMb2yGsjR3X2I0l4uZK/9pOU4YPPqjGNEA4ozBLnyyLRzRO2S1G
         sLFrb7aHKKuN1AWhgaVZx7lcNojhEQsDseGlGF3mV1LQDZ2g7oK4V3cAtln8eH/7vzhn
         BN5LEAhigtqDTE1wlT1DAhnWzT7fleKBM+So0xjJE6yy5jav0el3dPV4jdG4NoIUuxH6
         e/6PqsbI5w0XTBg4peExsAHHCCIL0Guh6ZBLg+Qed6DP13/pE5YhJuAhmLKVFiIVdTNs
         7QoWQ+uUIAxhF7jtVVpEt3cZt/94DWsRWkblXaAxH/lDat2r2nYJA1TmC0LFkES2Q5Sw
         Y5JA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HLF7+cJE;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8fd37f8435si210779276.2.2025.08.12.06.27.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 06:27:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-610-l3ZgW3CKOGqqNd4zvWIV_g-1; Tue,
 12 Aug 2025 09:27:12 -0400
X-MC-Unique: l3ZgW3CKOGqqNd4zvWIV_g-1
X-Mimecast-MFC-AGG-ID: l3ZgW3CKOGqqNd4zvWIV_g_1755005229
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id C128018002C8;
	Tue, 12 Aug 2025 13:27:08 +0000 (UTC)
Received: from localhost (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 9513530001A1;
	Tue, 12 Aug 2025 13:27:07 +0000 (UTC)
Date: Tue, 12 Aug 2025 21:27:02 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: SeongJae Park <sj@kernel.org>, linux-mm@kvack.org,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all
 three modes
Message-ID: <aJtBJgC82CpUkwTi@MiWiFi-R3L-srv>
References: <20250805062333.121553-5-bhe@redhat.com>
 <20250806052231.619715-1-sj@kernel.org>
 <9ca2790c-1214-47a0-abdc-212ee3ea5e18@lucifer.local>
 <aJX20/iccc/LL42B@MiWiFi-R3L-srv>
 <b5d313ef-de35-44d3-bcbc-853d94368c87@lucifer.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b5d313ef-de35-44d3-bcbc-853d94368c87@lucifer.local>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HLF7+cJE;
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

On 08/08/25 at 02:24pm, Lorenzo Stoakes wrote:
> On Fri, Aug 08, 2025 at 09:08:35PM +0800, Baoquan He wrote:
> > On 08/06/25 at 05:26pm, Lorenzo Stoakes wrote:
......
> > > > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> > > > index b5857e15ef14..a53d112b1020 100644
> > > > --- a/include/linux/kasan-enabled.h
> > > > +++ b/include/linux/kasan-enabled.h
> > > > @@ -8,11 +8,22 @@ extern bool kasan_arg_disabled;
> > > >
> > > >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > > >
> > > > +#ifdef CONFIG_KASAN
> > > > +
> > >
> > > Shouldn't we put this above the static key declaration?
> > >
> > > Feels like the whole header should be included really.
> >
> > You are right, kasan_flag_enabled should be included in CONFIG_KASAN
> > ifdeffery scope.
> 
> Firstly I _LOVE_ the term 'ifdeffery scope'. Fantastic :)

Learned from upstream people with expertise on both english and kernel, :-)

> 
> >
> > Since CONFIG_KASAN_HW_TAGS depends on CONFIG_KASAN, we may not need
> > include below CONFIG_KASAN_HW_TAGS ifdeffery into CONFIG_KASAN ifdeffery
> > scope. Not sure if this is incorrect.
> 
> Well I don't think CONFIG_KASAN_HW_TAGS is necessarily implied right? So these
> should remain I think, just nested in CONFIG_KASAN, should be fine.

After investigation, I keep the CONFIG_KASAN_HW_TAGS ifdeffery scope out
of CONFIG_KASAN scope. Otherwise, I need define the dummy
kasan_hw_tags_enabled() function twice. I am personally not fan of the
style. While if that is preferred in kernel, I can change it.

#ifdef CONFIG_KASAN

#ifdef CONFIG_KASAN_HW_TAGS
......
#ifdef CONFIG_KASAN_HW_TAGS
static inline bool kasan_hw_tags_enabled(void)
{
        return kasan_enabled();
}
#else /* CONFIG_KASAN_HW_TAGS */
static inline bool kasan_hw_tags_enabled(void)
{
        return false;
}
#endif /* CONFIG_KASAN_HW_TAGS */
.....
#else /* CONFIG_KASAN */
static inline bool kasan_hw_tags_enabled(void)
{
        return false;
}
#endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJtBJgC82CpUkwTi%40MiWiFi-R3L-srv.
