Return-Path: <kasan-dev+bncBCKPFB7SXUERBQPBV3EQMGQEP7ZSLFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5D30C94AC9
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Nov 2025 03:49:38 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4ee0c1c57bcsf94989071cf.2
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Nov 2025 18:49:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764470977; cv=pass;
        d=google.com; s=arc-20240605;
        b=SvfZ+ENTO55zNE0Bf+hJCITS0MrAMGqFXcdFBAJqKNIJnHAgb7EYPZuq3oe/W0a7N/
         sNmINbARylyJXhTP0uWme/rF3FsuLV1T7FUaYi9+leGxvcbZX7aHyINr+xhzYUpXM6ok
         RG+zWm68qA9Vz2vS3d6wnqeTWQaRBTiVfsiFkQjG06JH8nsV9pgC8eJgzRIq6vDXdLfx
         Te5AaZLpUzBRa+E+/c57k0Fbh251RM3NMZQWQiAvUpt/lMeXJHfP3NDiPeSkSyRN98O2
         9CGbijrni0LZLrGEsPHmY0h1b07FFZf8NbjSaY6YLdVDhmO85bM3++WxmILZbaKLDhvn
         Yuqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=vV/GDbynuzREoLvr0IXWzdyBKcumiHN0g8CIpu+M8rw=;
        fh=nLWUkK4Eepg7+bf9LdDxyB3Gg+z+Diyx9G2Rq+86RNE=;
        b=T+AvmujDJtQqDtosbbYocYpxYtT3U4Je3ufo91dYxj7LtfOMmugBif67xrJ01cE4SE
         +EfLd/2kQsoToaWqXtltrHefjXnfpTtoj82Kbcej9/e84Fq0UOcL52w6iZjZGD3Nol69
         kbP/LDHdUQiUDGgVyvMwkUn5RjKblZx3Cbcae2CggdgDQnTay0AK+PvwnMForWntyMQj
         bIS6ixKOQqjr/AMnQ41YcER9gR7zJtW9S1dMDSOz4Clzry7gCP1fZ0rPrY1OcLpIEVSD
         ns/dSAcnOrinpdlU/QWgIo1HYahtWLyltn0TxZQM2vpmK8eUcWTYh7Bm6Qk0m5k7+dsa
         5+qA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Cmp4BN+X;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764470977; x=1765075777; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vV/GDbynuzREoLvr0IXWzdyBKcumiHN0g8CIpu+M8rw=;
        b=SxgUhZujvEjOMHj4f32xXuPFoQNa+AiWyoj0WPU7R0MCdCL/rpH8Fjrsg+p2J5yn/A
         MntClAEqBozn/3AkCBSDZ4VY917esSbOsvgOp/Z4MJ263Wn0pmUh6WMtovKOBXMtY+G/
         9VBa2ItSS2wGwRl1kPtgZcgkS4hq+/9sPltCsYBnV426mGN7EHi0vPc2fauBYMSXU7ad
         DySBIRfdB7iUhpGiAcDBkX2qd1VlpQ/jS+6UOgNSftJqr/7tXHjFgBh3dQP87+l7+kls
         pXXzO6OjnlLXyozE4Sb5U4aMVcA2B5NEq/zOEuRuGoRk4VzxovkS8VTLH19uoqKOi30K
         3t8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764470977; x=1765075777;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vV/GDbynuzREoLvr0IXWzdyBKcumiHN0g8CIpu+M8rw=;
        b=IenHwa9+vZ2ZjQlL18Qu655zgLkTj7UEfWWHL98DOHEkDbepL9nAyXFmKNjd6M/aBp
         nCcNklddCXWks1AeJN5lV9vdfQ2zBL3LJjHHSuH66hstFCgFCrGYq37MoWRqvhQCKT3D
         LVH7z1GlO9P4Yfmzl8NqhnRguNVPYo/UOJ0bUWl5N16wMAZnNYX1oJJarXPPXhwVPDiy
         5BTmwOmK0G58nSXSka9/vt0jxIOxqU716N3IMx9RflSb2ZO/U8B255hK8DVA1xXideFI
         z/lef9FZCj/2WXwIbKnPdRz/a5mPglGWgDN9UIVhJdXxQ1YQSblEX3bH6Dw4GPkd/9N+
         ckdQ==
X-Forwarded-Encrypted: i=2; AJvYcCVx5BPv8uOLqC0ahcUadT7lCkE6mPCYXuveZHtmM6ogvaIJ1knKx2m92onLzdwV1a8MZdWSkg==@lfdr.de
X-Gm-Message-State: AOJu0Yz2O4Q4S29h40RsVja5bA115bwZOYviqHO/K7NzFYGHCwXNVpwr
	kVKhwDTWvpjQZO1BVT034uzAf2uVyHAki0S4R1Tx22udav3YRkE9goZO
X-Google-Smtp-Source: AGHT+IFjEWx7W996Z8mKbvIRYI41S+abs3x3FvojoF+ckygYs5JaZPMO1XlrLpC8JWDzaXLODmajAQ==
X-Received: by 2002:ac8:58c4:0:b0:4e8:93a1:7464 with SMTP id d75a77b69052e-4ee58a44081mr422422821cf.15.1764470977253;
        Sat, 29 Nov 2025 18:49:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YfcsexxymIktwvor4m2V0KGBEnEpCgFuLrV7hb+agOjQ=="
Received: by 2002:a0c:c24e:0:b0:882:4b1f:a80f with SMTP id 6a1803df08f44-8864f7a0a5fls50834186d6.0.-pod-prod-04-us;
 Sat, 29 Nov 2025 18:49:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLWZ/CO8sxzf7kO6I1VURAeLzu3UyAk62N0Jlxkc9bL0ai4zEP4Gqyst/shg0n9fk9Ih+Wzyuvc+0=@googlegroups.com
X-Received: by 2002:a05:6122:5207:b0:55b:9c1a:7c04 with SMTP id 71dfb90a1353d-55b9c1a7ef1mr8401029e0c.8.1764470976287;
        Sat, 29 Nov 2025 18:49:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764470976; cv=none;
        d=google.com; s=arc-20240605;
        b=RjgalKV3ToFUMX1V9Xp0jKgXZB8QGcgcXTMTEcANZ/3Gzl1mPryk8zIGACRRZazyUJ
         hdnbrVQQwtKxFe6zhMpK3+qwKT8o8Z8WpG7hZTHw0E0Wq0byXLe4YwCQqNJQlIEQQfVv
         IAj54/CqE/9EzfzMLB0puymAgnS8TYKgggvi3GWNYVX+Jl4OUNrJREVXlhVHaDn8RRKv
         zRSEBIK3TwISqG68fSoHwgpG9/S91MCM8a9kNr6rYL7ERxvdgGMhg9C0IrqlwB3fifME
         zg++DhNAtCTZy/2KiyO7sjM0dddNQp9ApyUlLXf2urT6zeeALs1XtaSReXZ9cL8eWDwy
         qa7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Og04/bt+yhEkeXfMP3slZPqApRz+VQNIptaZnXqjJQA=;
        fh=Yovj7mq9oJWSBncjdlOV+x6aBZP6F0tZ9s7tjLtf5ig=;
        b=Mu5Y7rz/QFIQb+W01C1KCOmr97ibyJsgthZndV5yvHBHf72gsBvZyPzjsfk6mB/osg
         tbRPJ0s/mWW7CkTtrxzowz6Sdwc/Jaa/vKOb4wNg9+hSRnmor21LbHpj4zwQM6QnKqaZ
         NDckFwUIwp6aIHTS/y7pHNa/zReBnemyC18pcXcS62PtL6ZqU25xDK2VguqOa6JFP2ec
         34FtQI9BX0Rd+4Z5B2VtjFDs+BdAEUQaQ+OK4iFNkckJ0bJ/S+K6ISfLc9mGFPT5fzVw
         gfbl5OYoFEnuOIX8iNGVOt4YcOCz1NFUWje03FFgQ4HaUelzN0U9fEAHozOSED0Sjc20
         NVSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Cmp4BN+X;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55cf4b0ab49si260498e0c.0.2025.11.29.18.49.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 29 Nov 2025 18:49:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-449--EjyqyECN-2YKkxJ_5cbUA-1; Sat,
 29 Nov 2025 21:49:29 -0500
X-MC-Unique: -EjyqyECN-2YKkxJ_5cbUA-1
X-Mimecast-MFC-AGG-ID: -EjyqyECN-2YKkxJ_5cbUA_1764470967
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id BC3C1180048E;
	Sun, 30 Nov 2025 02:49:25 +0000 (UTC)
Received: from localhost (unknown [10.72.112.6])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5839F1955F1A;
	Sun, 30 Nov 2025 02:49:22 +0000 (UTC)
Date: Sun, 30 Nov 2025 10:49:18 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	elver@google.com, sj@kernel.org, lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com, christophe.leroy@csgroup.eu
Subject: Re: [PATCH v4 12/12] mm/kasan: make kasan=on|off take effect for all
 three modes
Message-ID: <aSuwrkCSxvffKAZc@MiWiFi-R3L-srv>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <20251128033320.1349620-13-bhe@redhat.com>
 <CAG_fn=WpLtVhhOfU3pBKbJ2P3ih+PX4oW+MKAAmHRW0onOgSvg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=WpLtVhhOfU3pBKbJ2P3ih+PX4oW+MKAAmHRW0onOgSvg@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Cmp4BN+X;
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

On 11/28/25 at 04:50pm, Alexander Potapenko wrote:
> > @@ -30,7 +30,7 @@ static inline void kasan_enable(void)
> >  /* For architectures that can enable KASAN early, use compile-time check. */
> I think the behavior of kasan_enabled() is inconsistent with this comment now.

You are right, that line should be removed. Thanks for careful checking.

> >  static __always_inline bool kasan_enabled(void)
> >  {
> > -       return IS_ENABLED(CONFIG_KASAN);
> > +       return false;
> >  }
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aSuwrkCSxvffKAZc%40MiWiFi-R3L-srv.
