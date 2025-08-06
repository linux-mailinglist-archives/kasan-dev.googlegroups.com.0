Return-Path: <kasan-dev+bncBCKPFB7SXUERBEOEZTCAMGQEMK2R2MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 60EDDB1C36E
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 11:36:19 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-23fed1492f6sf98535025ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 02:36:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754472977; cv=pass;
        d=google.com; s=arc-20240605;
        b=HqdB6TlWs2Ct6X3XkQlgyT4uq6QBbO1DtHCYetMiiFM7bWgPKjS2n3OlRXWKvcUUzj
         uuC1fvsQKDKa3Af4srd+06Ms8++8Zi7NOZiCTikYyU8cA8xVPERCaJYUF1dRdn/oTWio
         PuK99rdbDeqI2Tp2yqIQDYB+MtOAbbAG7jP0IQZL3t2xwJ8jC1deJXBiZJnsgMl+kIZV
         7B9ilg2VLm+EW8Oi2Zo9kFJy+5X0czMgOBPc5l3ewZoLf2cWuup+2PAMuSNLt+pBSIPh
         REmN8XrX+wVh5vPKc+DLZMi/oQ2LKmeaPAVfdUJIaLbtwqCxNQ7e0JwcV8gsH5Wbz6QN
         4MUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4qxd9Dq9Cp70AQM7khNGET9L+357OaoD108z4TFpE1k=;
        fh=EPMiIhdfpjVnQUkQVJbJllSjxyZxg89g5sAzE5ibWR8=;
        b=jV7GZav4uzlRKimhDimIT1G9VCQ2QAgp7VudIi38IgWwwscU3/qtbE9cPZ5z2JNMBO
         uyWEX5gULj6+m9grhS1nDHwkEyxhfI5Rf/SoqCEdpFD/JxWkrJcVV7HSwQ1dGtEUhxMS
         xjX6WePpehZRP0HohYTrh6pIuFM28oEAAcyJnP1UJ57U7WChoa8oYywD7Wm6aMGd1y/U
         tDTL+50U6twAnrssdHqcrsjJvZ7Rv3wC7t09EXHARUdS2ff5QIYjMhU0bzsUh3YELbyA
         aDsj3NdUZCzyyO7p5lZbPSfhPPjGDBNBW9PRZ+1vqS+UvKBd9plOD0D41vHtDFyWNzyq
         7YGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Afit54FH;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754472977; x=1755077777; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=4qxd9Dq9Cp70AQM7khNGET9L+357OaoD108z4TFpE1k=;
        b=MB7RZgO8RgCPl5/ib7rVaT29Y3OFiOuq7T7iUcY3/QZu2olh95XSefkdARY1xvTXsO
         Bt/pH38swPK8A64bxN1yEo1vVoKVMKGsnsLvgnkb57IAcxd5rxeMoMLvtHTQe7VwPD1d
         JjMlAiqKBoioM1PK2TmDUD4tMbCZ5JV8ieDyrcxotFjM0Q9/zOI7Rf/lvzHx5nk/D0AO
         jLWDYchFXzQRhRKY3jNyC40E62UAcO2SFaPBcvQAGvzNJq/h5s15/Lg3ZC1tbKCVfk+3
         j/wRKzJ8bRQf0EL07/PwRJkIBYGRZGodyfoZc6R095JNPtwMo6XiPV3H5IxONew2i1il
         tYMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754472977; x=1755077777;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4qxd9Dq9Cp70AQM7khNGET9L+357OaoD108z4TFpE1k=;
        b=FAsDydDyV/fY/e689AVj2JecfxqVP7aTbF/BdPj221DvfCrEyJJ0VFz6avIMGA7xXI
         s+AWOZ0WpRgKpEnfIQXm9wcIz/VqsXWcIuhz6879o76WVKoFfX9zKW1ltdY4EvAl0g0w
         b5XkmptInfbw7oZNmr+Bw8W8sXKj4Qt4HVznpT2LXx1FsvP/Aqwbj1827IoKNdrvOOSv
         C4qjkn2nuA6vGCOeJVk4284CM6Y7LGgijzt7By8YWQVS733EM3mhg1yYFnlrNcQudwFJ
         qnyeiLvnDBKMiOg8Kly429hvLsJBngaG8kCN0joJt+GCMt6SeBzKF6tUWWUGfcQkZedA
         LD/w==
X-Forwarded-Encrypted: i=2; AJvYcCXAUZAGAYcvMViwNEQn25OneuizLVdzXiyhilVWygLXBzK0Lo3TciSJv+qdid30CieFyqEZvg==@lfdr.de
X-Gm-Message-State: AOJu0YwsEUXhKP84w66PKH0EkIjvw+2Fuyle2cX/ABHFUYx5VW6XWt6j
	NSt15cJmycWgAJmWBHjybfGV1LF3MtUEI73PSztZyMaVw/tpH8Q8SWN1
X-Google-Smtp-Source: AGHT+IHu0XZondgMqVQQEIfzJ4eaHOf34W23rU5Dnsis58zLWwUdXSscySncCMUvwiFacDAuMFsdew==
X-Received: by 2002:a17:903:46cf:b0:240:48f4:40d5 with SMTP id d9443c01a7336-2429f5340a5mr35648235ad.39.1754472977411;
        Wed, 06 Aug 2025 02:36:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe9CIzYarrw5/nxZu5Tgm6AQ1Mvn8POS89/xSlDsqFWLg==
Received: by 2002:a17:90b:35c4:b0:31e:b3c1:308 with SMTP id
 98e67ed59e1d1-31f90d6ec3cls6976032a91.1.-pod-prod-06-us; Wed, 06 Aug 2025
 02:36:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXN1FdBeFqyQslYMju1UsglG/x7t7Tq1hkZ9q46njJsssc+rIY/E0K0IrnHLbUgRwix0pH7RTSeKgk=@googlegroups.com
X-Received: by 2002:a17:90b:53c3:b0:312:e279:9ccf with SMTP id 98e67ed59e1d1-32166c1034emr2814078a91.5.1754472976059;
        Wed, 06 Aug 2025 02:36:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754472976; cv=none;
        d=google.com; s=arc-20240605;
        b=Pr/mDiBcZfCtKs9L6kMfzSsdg8mhO3lBF+R/JKLmQw8JBb7Dg40/j6GNZC0ahwwuMT
         +hsDMlMZg8UMtXMgcpI/9B79FZ2IUR5Vv8v+lRbKW7hR+hclNfr/wtBZvWY84oOfcxwP
         K2GWsJMxaB1DiRb849CiNsf/hpZAqjTNqdPVfk+Kas52krtP3wjlFjxg0n5n8MMgY2aC
         DRaY6kQYqeFc15Me8TGEnKFpIEeWF524kQHAteoZUPRODvHVYwMt//Lb8bZ5B08Ms6cp
         32sKLWMBNCqBepdf15dV/CmuoNgJBrAEidr2CRcZ3CW319yRsB2FL6fszsUm3O4fULhT
         x7Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9lYYsLzSzPrboBgIaB2CsUlJcp8uiiPFpeJB8b2vvMg=;
        fh=poqpGyd2oGwTCE30oAI0eaOwbAcSKG7LZ0MG8j3ot1g=;
        b=Fv3jsY3Jp+cEYp7muY4X1QW/UHgYFKzHv/zJuq719sXYsSmZIVOChrakY7BIjyY/h9
         K/LGD4z5bK+hbStkTNm15Le8OtLwUHfDjiMiYZ9bc6E7xR3/fXbo17g52gwHgUq9GL2C
         uNnqy2+rvOzovCR6g5zUT5ZCyvtoHnqjN3zo+2o6XnJBGCgrP4Xf0jbp8q9Mk5A2TNbm
         +vo7aGEFllyeC1EzCz+VdPkQE3d51KH17Yx0J/rGWghe87c6DVAywfgi8E1PN/QzFofR
         sHFjQZeVJsMUj10W5mlwjiaUnBiHvecxo6lqd5TcvVLNq1F8N/tW2b7m3Uw4BHbKSX8u
         1JtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Afit54FH;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3207ec5d581si755581a91.2.2025.08.06.02.36.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Aug 2025 02:36:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-395-UFCNoUSGPC6BIOrNHzU-2A-1; Wed,
 06 Aug 2025 05:36:11 -0400
X-MC-Unique: UFCNoUSGPC6BIOrNHzU-2A-1
X-Mimecast-MFC-AGG-ID: UFCNoUSGPC6BIOrNHzU-2A_1754472970
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 1772619560AE;
	Wed,  6 Aug 2025 09:36:09 +0000 (UTC)
Received: from localhost (unknown [10.72.112.218])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 791923000199;
	Wed,  6 Aug 2025 09:36:07 +0000 (UTC)
Date: Wed, 6 Aug 2025 17:36:03 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: SeongJae Park <sj@kernel.org>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all
 three modes
Message-ID: <aJMiA2hh3S9JCqOu@MiWiFi-R3L-srv>
References: <20250805062333.121553-5-bhe@redhat.com>
 <20250806052231.619715-1-sj@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250806052231.619715-1-sj@kernel.org>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Afit54FH;
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

On 08/05/25 at 10:22pm, SeongJae Park wrote:
> Hello Baoqua,
> 
> On Tue,  5 Aug 2025 14:23:33 +0800 Baoquan He <bhe@redhat.com> wrote:
> 
> > Now everything is ready, set kasan=off can disable kasan for all
> > three modes.
> > 
> > Signed-off-by: Baoquan He <bhe@redhat.com>
> > ---
> >  include/linux/kasan-enabled.h | 11 +----------
> >  1 file changed, 1 insertion(+), 10 deletions(-)
> > 
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
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
> >  	return static_branch_likely(&kasan_flag_enabled);
> >  }
> 
> I found mm-new build fails when CONFIG_KASAN is unset as below, and 'git
> bisect' points this patch.
> 
>       LD      .tmp_vmlinux1
>     ld: lib/stackdepot.o:(__jump_table+0x8): undefined reference to `kasan_flag_enabled'
> 
> Since kasna_flag_enabled is defined in mm/kasan/common.c, I confirmed diff like
> below fixes this.  I think it may not be a correct fix though, since I didn't
> read this patchset thoroughly.

Thanks a lot for the reporting and fix. The below code is great to fix
the error. I reproduced it and tested with below fix, it works.

Since there's other reviewing comments, I will merge this into v2 post.

> 
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> index b5857e15ef14..a53d112b1020 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -8,11 +8,22 @@ extern bool kasan_arg_disabled;
>  
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  
> +#ifdef CONFIG_KASAN
> +
>  static __always_inline bool kasan_enabled(void)
>  {
>  	return static_branch_likely(&kasan_flag_enabled);
>  }
>  
> +#else /* CONFIG_KASAN */
> +
> +static inline bool kasan_enabled(void)
> +{
> +	return false;
> +}
> +
> +#endif
> +
>  #ifdef CONFIG_KASAN_HW_TAGS
>  static inline bool kasan_hw_tags_enabled(void)
>  {
> 
> 
> [...]
> 
> Thanks,
> SJ
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJMiA2hh3S9JCqOu%40MiWiFi-R3L-srv.
