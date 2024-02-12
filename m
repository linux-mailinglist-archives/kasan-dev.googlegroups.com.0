Return-Path: <kasan-dev+bncBCF5XGNWYQBRBE5RVKXAMGQETXXPRBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4577B852138
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:15:48 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-59922b09256sf3798564eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:15:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707776147; cv=pass;
        d=google.com; s=arc-20160816;
        b=HpvRjTFI3pY2g0ICOSKo22mr7DChzdHH7RHmTIM47BLi5KOOlB1R+VKT7IXhwdsfcm
         42e9auSHHlGRuCLwTJa/aCIDGws+clvJBO7ul4vUPtiEnDbSaFT9yQih/s+iNanTXpSW
         w68iS8u/I0Go0atQtaS6/N34nrJDR+keOtQejoxTy+99DlS7BszxEtOMd8UEzLzTUK4m
         tpfEg2Vik9WY7L901rYo2eYh/nquzJCrrEAbvLQnICEBeBUyxnn3hbTWzEZaa/vNeJoF
         oAWOKUQpIhnO644MEYaW39xRJmA7d0RfbSFDojuhrAGwWYTDghVSv28G2hbBmdwt/ujh
         1GPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Gvw35Bw8rL6Md3zW+XQTXTSnk3AemJfk2FfYOpFFNmQ=;
        fh=V9M15PcU7V/pA6pjREJgPS9HD8oDRyFTV8eBKZNwAtI=;
        b=MgiuYkp6mt1AyTS9PQJLw1ESH6v6EUm83z5aCruHi4gjQsOICw8HR+DSp25pzsPHDS
         octFtuEvpwTLmfdXa6qw8cIHuIT7qQFigbih1Z7y4S9YzYGwQU5PVTj/bEthX1zNhUmk
         LsamiFYRJdDHX+bDjHEY7PALy+W5V/YUCi9eE8M1I6jeO47bajWeKNAbE8ny0MoIHlv1
         GWUisOORTwY5F4KhDQD26kfcm146E9PTz19cnUQ6/uL4CRUMHSN6jXWpfSeS7GZaLqbP
         0eBZsDATsI9vb/eYbCGmVBCSC+su2/K45J27G3tz7T+GlwAydNURvumbqEi5ijbQgBi5
         3C4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=SkegQIi9;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707776147; x=1708380947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Gvw35Bw8rL6Md3zW+XQTXTSnk3AemJfk2FfYOpFFNmQ=;
        b=SSIFCGp35Eu1oiw4spcf/GoktqW8PzoDxrhyevUkOYuebWACJ8ngCawGouYfHwk0sZ
         oiIqdwa58ZytLCD30WiyIKP4A6qLmcJN3HwyqpnH/vuGvdSf1KhFO0m4R/4rvvs9D2aF
         mXnSK4qQI4MCZoNOFNhgIZRHxHf05dk83lyS7sKK2KQK3mmFhVgTuqAM+/Op/p1N0u43
         ncUYD2tHmaVBusvG8DHBTeoYG6eNXh4Ou8mrlHX34++fBjkRtSVZzC7BZmLhLL6Y09aw
         gS12Knx7RtTavoCoQePgLp+8RbtcxuA/J7dBMG0Ra6/maJfDn3BkhEN+Ge3dEIPlXhpb
         gGVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707776147; x=1708380947;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Gvw35Bw8rL6Md3zW+XQTXTSnk3AemJfk2FfYOpFFNmQ=;
        b=S4rUBsY4EZACWuw0WNKJPIhB+1wfn0U/WF9CxhdkaCyvie/uHvG5MvZC3l75TrOZgV
         7RY/HfxFAPTxEG2phQNe1ZJt7OUMCuFjJO8Q1SRNf2zYybTcHGSudqQnwqHTLgVOjfkb
         O/9dD+/9xLUmNqsHnIe40cdmueFenLSTkY2AukLyjA0fPcOUS8po9o8Y6BByBZA1N13y
         XiTXrSLrm92M3euNcGtZKhTiQlWoLUlWXPHMek2zQePWMwYyWbOkX+Wh97Zc+Gu+ANg/
         bbVb8K3wf382RaNnYnXWflzQ1W9EMDrA//TGkNg5VH83tYJo7ifNzfJuD9VEmvndxeqL
         /4nw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWOuhaHrswiZbTKVBofDoGQnbsHWClh+zL7eUBdIy8AixPxP6m10PMhgwdsWEgItPffP2qfyeL+rjl+87UTHDtUiMJGfe/b6g==
X-Gm-Message-State: AOJu0YwdoaqwBMpYJgLAYoDnR5623YQ9I42osmwn2I26g0JBpfa0STBT
	oE+oInCRPaw2rtUOG2Q+jJTO6W0qYqCU/TWOSMk5nn2vJU+CRn+k
X-Google-Smtp-Source: AGHT+IFsBLW4T34TW3DVe46ONI7QNqxlc3YZRJ07kChP/hOcTemOs66RhSBTgNu3z7XLmqhZCDgAfA==
X-Received: by 2002:a05:6820:623:b0:59d:46df:dd3e with SMTP id e35-20020a056820062300b0059d46dfdd3emr5915221oow.6.1707776147192;
        Mon, 12 Feb 2024 14:15:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5a02:0:b0:59a:8b3a:f328 with SMTP id v2-20020a4a5a02000000b0059a8b3af328ls2778119ooa.1.-pod-prod-08-us;
 Mon, 12 Feb 2024 14:15:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV2n5PElHrSZHeTN6vDCkGa0Htwcf46mxr7yR+2oCfrZc8KzMW2XC/dfWKvjifoF2xJpMAqldts9UuzGsDA1d8/WIut5t4opYebVg==
X-Received: by 2002:a9d:769a:0:b0:6e2:b689:c38f with SMTP id j26-20020a9d769a000000b006e2b689c38fmr7577660otl.27.1707776146497;
        Mon, 12 Feb 2024 14:15:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707776146; cv=none;
        d=google.com; s=arc-20160816;
        b=xej5FzBiBdEkhQ+d0RacLxLZ3pqG3dEayb78nQ+YD6MP5eilQYdgQJX9HZgKMm6yql
         iJJ2AbszPZZ6sXEGcqeS0FSjng79V9BMRWC2qRTontwoKxAtzTHY+batKoIgzsaJKCPK
         yEpMb5DlOaIvKHFNvjItrGAQ4PZ3hzj1el1VIev4ueESTvecYO2FgPT21vebPE5Kd8RZ
         E83PeOLfdEg4ARj8hpCexZC2xsU0JcIJRPYl9KDa/c1eA1unZB38UoNSGE+U50TtAljC
         YVU2I3N58AGgVA28iZMOJz61KNbWjcFMLFxmXwyE2i2JRieeRUPHVKQv37bXn7kHYsWe
         RoFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Vrm2VgfWvTQwh4Ccc8xLBpbBJbaIpSksAyHKgKxPeQ0=;
        fh=fknnbyImmMTJeFrSdveYeHJp1HJMabWEi6aMn3d5lmY=;
        b=Nqz+mJnldWZPhAvp7A7khzFByHxCT32bSnFpUGAqUjRbmltvk1spxFL3oNW4NXwxcO
         kHmflm9lmQMfpkc2wu4mCYKMFXUdfH7Ty0ZFW9AT/dGLRK3JdYJ88COdaaycFf0yyAw0
         yBGLZEjkYPfIGqBGrJVSUKBVe63uKXQBxxD8wOQ6FyPiPKTaojXG4JJzcY4aT+S0YtHH
         gusUZnqz42b0a8bUUniTGnBIsSmEzvg/VKbhFVXCim9oJ8jar5B1Y0Z1tajGzcA1j4jb
         IP+5JI1PrKhEH/2yOgln95+uB4zGBMNzaauUdEdmVO9+qrbK/q4Z3gbuwt+aUsCdvgGC
         xB4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=SkegQIi9;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCXQXGv6P/Ai80vuRfG7W/P1UeeP3fzGX3Grb1qbV2tUX2ev4rvugzjLlQ52scOS78AyEtHvVYWvH1NdxOixXKhVqpYbiNegX5fzsQ==
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id en15-20020a056830488f00b006e2db0e0043si168870otb.5.2024.02.12.14.15.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:15:46 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-5d8ddbac4fbso3293267a12.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:15:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVIWRLwl0Ehp3IhMabs78IiHzYSEPTKy/RWcHgSLws1/Q3J+ipdX7+jdId5d5D7eMt0aSsXNG08FIoKOiS0bl3c0DCj1zp8Q0gMaQ==
X-Received: by 2002:a05:6a21:3983:b0:19e:caf3:87ea with SMTP id ad3-20020a056a21398300b0019ecaf387eamr8576297pzc.49.1707776145852;
        Mon, 12 Feb 2024 14:15:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUiMkS3EO0LECniHO822e9YGRztrIHXu9VcRsxon8KGxgqPIZZXsI/wP7GEiIc8/ANrOOWiQ1j95WqRqYE0fwBkYqCyhmqh1awBxBbuT/vAWCWKrmjjIXU5govUofIc0qlffIDcU6Wh5HDTALZ3Y2VtniOYljVl0XoGUE7D9Ro9BFNn2QuebwvHDDffjsEnPEG3LRU5v9/yPejSXaxtKzy/HV1TKfjQlJRFbgqRkgqkKVawqjX/olJFHzrF0XR+l1Rn+CPzbilU1FdQOPH/XFJs5L6GXtPBjlC0ebf022wIXYlrDqbrr9m4Ge/wW+pPEG4D5+JXSiDcZ5VqmWx4j499zqXRL+Co+TlNyH5qIgZQFCsNq/q743H4NgkzgVNpkKxb0k92Nx9hcAUmdccW50SYngoCw5UcMr1dScHJNoNW7ABOZevJ2V9V3PzDJ/sPlhdfgjkQbSCimt5r1kx3oKyu+ZEOglgUcW07qVg+iCv8CBNgF98khp9ss1eiWsrSUcSdOyZNZzAQw/75MV8mp90eQVj3f5LQpp6SV6w3XGgfAdZJRDxThDPTXH7zBocJyI+cnaelAgfsZHScmbLwgVmc8Xg992hyEhtgBDeT5sm6mKT81eZcN0c1kZebR8w0Iak/FHT2Y7asSXLOIIIJAH1WE5jJx4efhkmOzIf58Q9eGV1UM/HOdBzYE0l6dbF0LhZX1km/eEX/RW88c3A6m0lAIosUALSdJKxmSlqlpVCLL6Lb5WYQgwgf1o1HgrFFHe3S4IgMfzl5lMK1YByMMaaS/slQfRZIE8SPX/8Eqhrfd4bf759Sa12da5aXj9dFTi+X04eWAzhVwFL/5A9HjNKpQ9y+WwxsQgANuHB5mqRGdhHmbwlAcZppFGEB8hdsHq7lSMom3dg4fCQyntjLySL9P8WeaG3n31vPCJUchf5C00zVengpD7AmTqZ5M8I6u6Rocp
 aI8+ql+kMCshx+CVABKVS+q/SQ3S0AbBuvXiPp/NX2++4/LmEy2G/e1vyeJEG7x7pjVNTjXiJDPKvydaUlkz+KGUDrtz2y890uXCAiG83S1nFszLQWW/u4/iZtQIbDPLn/fHLKrPuGzEhHFc1QYVlloufMNtpsc22VRryI7M3oKCe0FHf/ooN7FsjBhcyMsg36/GqVwDncyKmtySdRzeMhSmANQXfQN6QDx34qIOPzfmlby0RGCq37SGOEbELwzLZ4bVDcjw4cxnP+RTAYrNFNu7Eov3+CqCC+lrE/0grBZ4awv5MKez0KvdwwKQlrSS5d3SozIIjqp2Ddg/u8C7npj9fzp03oD0j2XosoAHKo9kmEIRerxIm+Hq6MC72s1VBuOzaGoN09JP1vjxofD03Y+pKe0i4XZqIs1mh9LC3iAZby/nmc23okO8U/s04=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id y2-20020aa78542000000b006db87354a8fsm6023523pfn.119.2024.02.12.14.15.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:15:45 -0800 (PST)
Date: Mon, 12 Feb 2024 14:15:44 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 09/35] slab: objext: introduce objext_flags as
 extension to page_memcg_data_flags
Message-ID: <202402121415.4E74908@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-10-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-10-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=SkegQIi9;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:38:55PM -0800, Suren Baghdasaryan wrote:
> Introduce objext_flags to store additional objext flags unrelated to memcg.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121415.4E74908%40keescook.
