Return-Path: <kasan-dev+bncBCF5XGNWYQBRB6NMVKXAMGQE2RNQ2NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id A8A1B8520E9
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:06:50 +0100 (CET)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-6077f931442sf4418757b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:06:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707775609; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDcmybLNsUXxDq1DpKESqfeLjUvWpaK39NgDM+ajv4jkZSEM9RR4Ij1T5FY9VSFTD4
         oTSgx4KcFROI92plUZHtrkwViYVWe7dI1qA7+77DiaVSj1PbKMtjuag16DCrK0Dq8RZF
         CnbaqSEWAZNiBd35O47CbXVK1zrqjuFgMHpXrcfOd8IbP0ufzzmqzwVvxRBxB5u4tk5X
         fMhniUCaM0CyTNpcykIfSKolQIylyqSDAX1IgPX6ba7ghJFYRG6Uwnw4nypX+cNG6CCE
         VjecXKWREuUycL5Dh5X9ijmFCWnXadXTKnKX/YFAF5J1QfTltNkXjamZ5Vz3bARBH8Hm
         zHqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HhjsWvmanldvLd9VyfvPRBXfm52hw6PbOqF5Ii60Rrs=;
        fh=hL+0nB6BNBy7txAUbTTLzvJb1Wi5bQUy+wVZg+AKW2o=;
        b=mJFF/Q8fJFam4Emt3BMBpxkQVHSxqwJNc+5fWMSgASXdrjsEkdS1M2KnjjLHedeAIa
         UXJX6f8bN2I7rjlnIqFvUlHWZVy19Xj4UBja3uGKSHACJd50FXAgydYmWHWvGQ8aVL0r
         GLqvbmnCsjmmN0WMiwZCZi+QA5l45ykGjIB4mqOvqwmcXBzH+SUCIChG7EjO/oLU/qP8
         e6PLrOYTi+XXB7p26X4HA1jkGqkLWXvEZhUuZQwpInYP72Z22djudFp1yKxHCNhKQZBm
         uLb9SokF2QFG9jlELiiAXFnmI/buCjAmls+HSj1gbKX2ruLBgfLyq4tt3y3mAXtBixEC
         F3mQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=a40TXh7d;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707775609; x=1708380409; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HhjsWvmanldvLd9VyfvPRBXfm52hw6PbOqF5Ii60Rrs=;
        b=DwwM8QmzjtMLf9owUqkMKxTCSJ1+POrLQWw98PKQsdNr94Yd/kmkjBTQj40h1Igs+o
         oc1sKJYKc28N2MNzkHRbBWlh9XmSh8Zloz4wuUOaAgivrf1Dh20chJ24H2WQoBc4xAHk
         pOYDS/cLxgP9yFMc/CkRAEN314EAw9HhbihPyYztrTTsFOiWqtm4msX/8YB8Hh0or/gl
         Mtt3O2ehS8fTLwBGOeXw7ZcadxbHUbCHOf0ureIUznQdxk2BFjyDr9Xgt/EfRSAO34DZ
         J6eo8EHfQBBcbERzzBHLGyO/1k/Rns3JHeDNWTnTanR0OZKfiLq4q5JI+QUPNz07TB8O
         wa1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707775609; x=1708380409;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HhjsWvmanldvLd9VyfvPRBXfm52hw6PbOqF5Ii60Rrs=;
        b=JgLbnmHxcU3RAF6kOm6tjDxVvrYJcbsDjSpT/ATwmpyLtOtApUnPWu/OlAH+JVscef
         pkXYXvLi/ZvSZ66mBy8KXjVVmldWlgNE7RSrYKaJ6wZ9e04VEMuYvjqAYHqImL/ItOhL
         qwm2aUizxBtOICncAotun11OSeiilyLA3xJnser12icq26OOcZnLOPiF+dnY+QxVaCA9
         4mZv9suXe1d2VUg4ITjdneRSq1wb2TCBwOAKzSn7zZvKMm1blF0W/RGnsiZadCBzMRL6
         56aq5kj6+CN5DfcDVlVPu8zKnn72F4FJIxQ8MrtsK7rR+X9HpLgH7oosT4pDu+isnA+J
         vaMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWHrZ2tn+2UtzFJEqNhbRl/o8SJSnp1jk2fA1RQgmfyYFn0VmmkJejRVyCu0aI3bGvcy8Ngr7XgjnwkRUX2FPCugAV9GvsYQQ==
X-Gm-Message-State: AOJu0Ywg/dmUa8QzJnh2VFCNBLXwFt09BNL30y4YLTnq5urg3lMEUd0S
	ZyvaBP+mSl/Z+RDn+UjSML9X+zsaDofmVxehVkPjiehVZhh+DpF2
X-Google-Smtp-Source: AGHT+IES3H4dPlQwlXmR6Y0qUDKgRhbxHUSu1tAuxYP/sQ60sT60CskylPUDU27CunOdjhaKNTSzXA==
X-Received: by 2002:a25:90f:0:b0:dc6:4b37:e95 with SMTP id 15-20020a25090f000000b00dc64b370e95mr7010736ybj.26.1707775609677;
        Mon, 12 Feb 2024 14:06:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:df12:0:b0:dc7:4960:a8a with SMTP id w18-20020a25df12000000b00dc749600a8als429294ybg.1.-pod-prod-05-us;
 Mon, 12 Feb 2024 14:06:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUsmTF5/MVrERu3FLZUpbs/ElYcuhTd2BKJsagobSzsoOPxXQ0Rx/s0m/wgyABLYftdToxZSt52aS8vXHCZjh2ohH14+mmJfc+MbA==
X-Received: by 2002:a0d:e684:0:b0:602:d322:8e07 with SMTP id p126-20020a0de684000000b00602d3228e07mr8191681ywe.12.1707775608882;
        Mon, 12 Feb 2024 14:06:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707775608; cv=none;
        d=google.com; s=arc-20160816;
        b=NrcPHGYqha71ppPKblHk3o9FH34hrkXiZo9AirNtlowQUZEmjieOAYVaMkXsWJgcb5
         p/1euoja/bo/luPtd6L9FBuPksDzFJI5DS9hIo+FQwe5kJTPiy9rfx1jMDiVhkg8ar8H
         D4HWM2OD7tR2cJt6NF6eERTeeXVS6iIxoc766YUxOSKHIoVuDBEf9j6vAwXlohlQFME4
         21RwAvIi5nYYUKpxzEnm/+4o74kjn2sPhHPk7U/AvW8Wjn968JfWLXD5vWB89dfK1lfT
         jEhDb5degtcr6iiSB5bYF36HvcbXnp+Zkkp3fQ5N5i1sWfYribG5Cx94KCmGaXA5wM+a
         GH4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cfBFT3E6uuwQvv/Pq6TrncKe1LxZZQMXwgtmc4u2niM=;
        fh=y8UtDmz2/eASVuSE7VV2ZS8/wtkmDrxLrRlMwtAhz8Q=;
        b=WoR8//1zMs6C5j2qfNYmOD/KudtNXy5DDSOcPXSIXhFxHxiWIqavWMocZBc8NAiPrn
         5rKxQQy9qFJCd4+d2N/t0sPG9dVYFTVJw4av0xukuxDr1eiVO4Wo7nzPDuOAVXH4Snz2
         Ns3UOwq8/eZLWjJFPRb499SdrYHzAfesP92aq8oZo29FtwCkbpwupNqBRLMV6ywqjMBb
         CUIZypAvLyjV5YXCAD5nqs91QfNYq69DlAfju1fXZp6vr3Y7LzPLp/EEp6Mnacjs70V+
         oQLG717fGkXuZA0WmLwmorgyO6zCGxV8+kliwTvMQRfa28mmbuiX135ZDPdL+0YOwZs8
         lo9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=a40TXh7d;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCXII6HyLZPVcGy1+pTiNIZy6IouwfTztep2aE5w8gZSDAVS1entd8XaQpaL4pjXujkSmz8KsWnHaCaDlWQZxS5UFaFKsOphPUp6HQ==
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id g16-20020a815210000000b006049b4bcc17si711444ywb.3.2024.02.12.14.06.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:06:48 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-29041136f73so2204787a91.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:06:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW5OfQ9TQIJHh8rr+gmNTQQtnWYACuMsiaC0LvK80RNu+UJUCErqVoxQ/Ltr5i0m0wRx+LsjnS4cB+JKRHqT7VkvI2kEvCbXnZd+A==
X-Received: by 2002:a17:90a:c704:b0:296:31de:b58 with SMTP id o4-20020a17090ac70400b0029631de0b58mr4390913pjt.4.1707775608347;
        Mon, 12 Feb 2024 14:06:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVtrBbnqnKEuHQahuCD1YGXGHf1W5Su1uidDz39CnIxfIzgNtlvCFJ10O+g/h1z3vZZG0AM8eDLCtMO5ZxJiukU1/1bFKRhMxaww7RAEwgsUNn5lwkxei62c6RJyp6z+tmFfUEpcb9YkkroOzl195suvWzZPgCjOoOvE08Ylr2TV4kpa2VN18yIoY6c9uwsk636DZMedqEbQvY7M+TBvP4rVQtDZiiP7HgQbhyZTVSXwGBRr+xx+OG3uIR+5bs0TGUDZ6k3K02hsdLn4SbyKsZhAWkUb9toGueNJZbyfZJSag0nMwIrXgQQ0PhLgHMbzqsK8Aj/cYPAjG9JoYDHPsJ4qgodKjp5NmChB0lnLRQOL1FzDm18UuOl3xqVmtL2WApHS8PNrceNUUW49wY8DReHdUAp94FTjapp43/Rb3Xz9uqBz5X5e+UYwKdfBFH29NhuaQwd7ixh7G+4EasiSBqbBAtwX2fPHhu5P7HAwe+1G3vnMpAuK4IniHwk0YBCPpYvz251mTOw+14DnscW4y5wfBGmh95tGZdRYrnbj0mwGC4oM9WEIE/rRyeI1qm6FkilKbxT4BlWf6ecs0Dr8Ws1IXilq/oLd+xl077Co8p4gM7FdvxzXEJfXkijoAuIlQ0mMom9EW7auGYhTt//jTJeLGQlxPh+QhfCA1KjQqosM2FomgzVsnZdxK3Xm1A26Royf4X9JExMeEYhOReuXD5fKb926z//rmEc6OWLw0i1VINjNR0J0Dhl1zWoihfI3cDW8+dgAimvHHNLvTpnrCgRJCmijSFDx1dP5P7b2XhBAqmJ7eqCQ2IJZ/17vs+FUxMbjqVhcryZRE44O4o7UG5HkIrtb8fAmvGSHlATw8w5RH3EwF2MOgl3ZdUOXK/X/l2VQSe+APH+jjiVaG/OorTFicSovGCNhE4kUdKFvg9cFLzEeFTDYLCmggxvMHOgZBBydn
 3IzEpNqu/5mw+l9FJmjhmpbjo5v91jgBtbHsHjTw5B5xxjgJCozxTd/KFsg2XzgtHFgoBQbl5TupXa/7nrdEbKnzYEqMgeyV97ADlMBiGbLuHzek92BBYiiCGV55xZ4xQE1NRuYLPl9PdTlAuzUeJ4hT0+rDzD1tJy0o6D0tsA4tvsh5oi3U+SSjjFkqE/3c/L/kSm2s1O9ikcBoP57Elijl07HiHjaurGl1bm7gg7KqH6YqsaMpR6y99RnPZXOCZ1W/Dg6FlOd0sV/NVukwjxf4MpD4IJt9lV+plpxgKtNnA7O1Q/cO8zD3pH4nkUNnbsK2H7ES/caQkcAdgqARsnkCBL48hsfO+Gd15hGKj0PJlBFYlKEllh9P1ztty5b7a3RoWaG5pE1UsE1pq7Lg8Kvkx4qPbF/ucLJvTItNEjjtyL9PB5tz+4RMOXbV4=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id nk23-20020a17090b195700b00296cc94faf1sm1036623pjb.2.2024.02.12.14.06.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:06:47 -0800 (PST)
Date: Mon, 12 Feb 2024 14:06:47 -0800
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
Subject: Re: [PATCH v3 02/35] scripts/kallysms: Always include __start and
 __stop symbols
Message-ID: <202402121406.16006BBE54@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-3-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-3-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=a40TXh7d;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d
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

On Mon, Feb 12, 2024 at 01:38:48PM -0800, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> These symbols are used to denote section boundaries: by always including
> them we can unify loading sections from modules with loading built-in
> sections, which leads to some significant cleanup.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

Seems reasonable!

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121406.16006BBE54%40keescook.
