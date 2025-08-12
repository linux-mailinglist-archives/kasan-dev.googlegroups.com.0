Return-Path: <kasan-dev+bncBCKPFB7SXUERBZNS5XCAMGQEXBMPK4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4066EB22B6C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 17:10:32 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-76bf30ca667sf10482011b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 08:10:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755011430; cv=pass;
        d=google.com; s=arc-20240605;
        b=OLjojFrEqe8nBtGuTrFTn6DymrMnO8XvUith3nKw0FhCbhymN+Rmqs+0psAVsdbsWv
         kKbspc9Jo62AVtfHCE8MDIGSXa6xEoGHbjsUffR/D12PkGLM3oral9S0Evf2eX0HGI2+
         yGLs96qR6fE2zrFqd9FQ/s69QDbVS9xMK1Zy5nm2atz+o+EMgp4bJW/hZLl7VX098yDs
         6vv2pniOY1Uf6t6goOlHDPoBRt98lqrYuJXbNTTQ6Q8IvAK6I1mWYjH7ApaE/UOV4jn3
         Z5oJba4EE4Zgc9tc5Hz4Oh12civC52qicYPoHdj70AQ0FxkX8obs4FK1h59r6JAPqFaJ
         sESA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Utx85iIomwzoT6ss9HiJJo/YzTS5oCk84GLe9LHcAVI=;
        fh=Mbq1hv38P8+Aj2sriSppCF1pQJRRrJr3H+QC9xzQdNU=;
        b=IoDAa3ooOBR2ps5rNDOOXFUwenuo39RjLQ8c/gUtbb9n9pu7rwbzfhmC+Ss5OPHEpJ
         9AWM5aRYgOzxagVH/ZnGNrUu+fiUq6Nwj3j02iznmlEgMEyQn7dzSu9b5FVmiSA8j03x
         IoR7OS/msMdOcx2XbaUYH/OYDbnLGhblt7C97Z0yxoxXAHi37HXfynEHkzsb89xf5d/0
         QC3IBSPufVNiyMOPfwgzhEZuPEBjFk9fi32HnMHIu1YbFEQpQAY+Ljd4I+XEaaDr3Uk/
         jUKByun0++Eg3XVNYtO2MDU9A3DjDEHYQI+uU7aE24y+TUfxkobd3awlbbD3TJ/LXJi3
         MJIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ibJ2W7Fb;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755011430; x=1755616230; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Utx85iIomwzoT6ss9HiJJo/YzTS5oCk84GLe9LHcAVI=;
        b=rn0YTr2eiHbbP67JXhwEIDxYJ+MQXX1Nbr4fZLZ9vvfrV+yRc4npeV5d09cGmnN3+V
         j9Hi9DDoVn0RwHx10E9AVFA9vPdntA40CN5S4MyqVTSuXSD3+HsZPfaB4dKCOAaoQfvE
         MAfpOv/O6N1V0MYlZf0nWoVxeDNtZMJtHoBGQQ4l0xfJSL/RulOwSe5TalRPNAPxVdns
         dAB320xDTxp25hrGSCDxpwCikgvVe17R4/Z4e15SNSAtoN5+0EC3ow7jFldcejA3viaR
         BOuewMPX54rHn5zrDtzri0iAKB31MhUblAYy9GsIQ7+WUAe/3gnlgYnvUEGynxIVlQY5
         s4iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755011430; x=1755616230;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Utx85iIomwzoT6ss9HiJJo/YzTS5oCk84GLe9LHcAVI=;
        b=eepsjPiINdA/AMmm5fRB7O7fvozOLDhkX8NwmOtMOlJ5gHMO+lUG15j/hrEv3uoCOE
         ti+gAcf6cI7mx3Zsd8d2CzK1CFQAD9vRdluFU1vHBu+T0LanJnE5uJYslPH8lBcdn/zQ
         0mX1GF0aqSZGmh16Uvx3aI5ZAkC5gk7NXsg1CN9sguXEj/dMiFBX3sni323UhQjQvS+z
         AcD8W5caYnIQIltbs/xFc2iiwzFhyYxx/EMYBFId4e5fswhb5/vI2lCjaL8T1lmajoYV
         SF9Dpr/ltqVC6+HaOTIE2LKcgQPwYs8wD91KZPxRM946XF1qfI+hxBfr7cQC3+PJN7Us
         3dWQ==
X-Forwarded-Encrypted: i=2; AJvYcCU4O4O/mzMLE8mLFNmZv/zT71VDEETjMmNFGkOECPemS4+fDYcIkC7JscCmeKy49Bft6uDhQw==@lfdr.de
X-Gm-Message-State: AOJu0YyQ0tDpsTIibCOhFGFColG5+QKLBUIllzmHQ1jV2tp37Tv7aGqX
	eMzDmGU/lo0VukaQip3Ra7QFLPLCKvN4cprS0GT7uG7xFFej+EHwSuRA
X-Google-Smtp-Source: AGHT+IH56WJs/Izhl40q3oKYQStxNDuerdTrhez63jbBJTMJ7n5jFVJI0bcK54bUYQRwiCs6lQb6NQ==
X-Received: by 2002:a05:6a00:844:b0:76b:deca:2b40 with SMTP id d2e1a72fcca58-76e0de629b8mr4620728b3a.10.1755011429840;
        Tue, 12 Aug 2025 08:10:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeowkmJioZbHxKjplQyFVYR4V8BzSKEudQNPZHMUSk+gA==
Received: by 2002:a05:6a00:2e2a:b0:730:762a:e8a with SMTP id
 d2e1a72fcca58-76c373099d8ls6665475b3a.2.-pod-prod-03-us; Tue, 12 Aug 2025
 08:10:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFuJRpJIVZ/H+ysiwkMjrLJn09Tl2FfESFenZTRxBLcbVv4gdSh3KFwWYWpNixgvbd1mIw7b+Z5to=@googlegroups.com
X-Received: by 2002:a05:6a20:7352:b0:240:2234:6835 with SMTP id adf61e73a8af0-2409a93f02amr5672814637.27.1755011428292;
        Tue, 12 Aug 2025 08:10:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755011428; cv=none;
        d=google.com; s=arc-20240605;
        b=lk075l6yeX4jiZ6B8L74JrsiKz5WXevpzcgW5Qg806PnO0qKKntR5a0S5D1Bu/TcSO
         ys1P4dKbq0XLBmHVGOjqATZFqWPdIads8EV0P/CZxrpOzxzsGkgk3eORBlbbRQpSmpgh
         lzxhMudmJP1cvmQ1AFSA2Uol1Ak3Mj1PRvJhTM5OSM2NZJmzQDextevDH1jOejaWcJJC
         3bU2uXtg1M92GV++nawaP2zJ/eO1kOquNv9CN0w4ETxQH72vsjDwwRY3HEWMkT9r6Xzp
         x1ewwgmXT+HF+gMjV3o8aztJ4mHnN46VR1JPjIjQcQhhK/oPQGnmITzBAbAWwnI9uSq+
         cMkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PrBFm9KN1k8udVr7PX4kpGMG0V0UIL0fa5o6pxCVKL0=;
        fh=7v8D6aOYeFGctAgqBMyjLhtFlWrV8cIQiujynBiMUfo=;
        b=bnT0Y22uVpG9/+C54heSyDWoxXE6kKgXmW6O+nfo9JdGR0GlSxwNhaVrLXAKKTR6Oi
         Zbh/VkHpkzHwZgZjKBdBeEd7zlIVAFjzv0K5uYoYQcZCW7r4m2c40uJGhH3OJtY8kBfH
         zu6NH57cxLL56ZfVgdOfheH1Ni/zs8atmN+ToJu7b9iOSawG97yyX1fJCArrq1EV/i0m
         WaY3OFC1q4qo25RUlElWEZXrDJZTApjy/rJZGNMtytJe/QI+q+DowViXLZG61rDFGofI
         5lz8Wcm3Lt3z2+KOVjXGHdkH5akvT02utkAAjoQj8eV+uWLs+icFIIUO/ng7mmPH5bE0
         8lQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ibJ2W7Fb;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b42346fdc00si1178306a12.5.2025.08.12.08.10.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 08:10:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-693-SghTwAjnNS-be_4HqIcxxA-1; Tue,
 12 Aug 2025 11:10:22 -0400
X-MC-Unique: SghTwAjnNS-be_4HqIcxxA-1
X-Mimecast-MFC-AGG-ID: SghTwAjnNS-be_4HqIcxxA_1755011419
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id D0E1D1808966;
	Tue, 12 Aug 2025 15:10:11 +0000 (UTC)
Received: from localhost (unknown [10.72.112.156])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4E3871800290;
	Tue, 12 Aug 2025 15:10:09 +0000 (UTC)
Date: Tue, 12 Aug 2025 23:10:04 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	sj@kernel.org, lorenzo.stoakes@oracle.com, elver@google.com,
	snovitoll@gmail.com
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aJtZTLPtHUfUsiuQ@MiWiFi-R3L-srv>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ibJ2W7Fb;
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

On 08/12/25 at 08:49pm, Baoquan He wrote:
> Currently only hw_tags mode of kasan can be enabled or disabled with
> kernel parameter kasan=on|off for built kernel. For kasan generic and
> sw_tags mode, there's no way to disable them once kernel is built.
> This is not convenient sometime, e.g in system kdump is configured.
> When the 1st kernel has KASAN enabled and crash triggered to switch to
> kdump kernel, the generic or sw_tags mode will cost much extra memory
> for kasan shadow while in fact it's meaningless to have kasan in kdump
> kernel.
> 
> So this patchset moves the kasan=on|off out of hw_tags scope and into
> common code to make it visible in generic and sw_tags mode too. Then we
> can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
> kasan.
> 
> Changelog:
> ====
> v1->v2:
> - Add __ro_after_init for __ro_after_init, and remove redundant blank
                            ~~~~~~~~~~~~~ s/__ro_after_init/kasan_arg_disabled/
                            Sorry for typo here.
>   lines in mm/kasan/common.c. Thanks to Marco.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJtZTLPtHUfUsiuQ%40MiWiFi-R3L-srv.
