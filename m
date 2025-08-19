Return-Path: <kasan-dev+bncBD66N3MZ6ALRBCWGSLCQMGQELHYYCXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id E9CAAB2C948
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 18:15:08 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-88432cc8949sf542769239f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 09:15:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755620107; cv=pass;
        d=google.com; s=arc-20240605;
        b=S9RSXlUn21L2LW0lC9Kh3wDTrY4SQss/ca9ehkvPeu6VajBjHJkXLPQHzkuRjNMC/x
         rxunDocJOOszQ+PwfxkT4q2eUL8Krue2K2ve2XlK0Eojw64jc5fYAIXSv64d3Gp45WMG
         6k2His72MFTpccUG0U4oPGWloGdQV6mwV0OTPWXtAPT06qEJpwukIT2iO0WNo0baL7OM
         QGncheFJEpsu80dcE3xXg4SJ32+m9J84wXY+ZiCoglSvBeQ04c29tMgl3p2NTAmjMIw2
         +ZOAKIZhiOqt8SbNwVxcI3lkCGYsQVlPNdMYw3flB+AqjYxHROPApvyuCt7cAggKJWZc
         HN4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4DpuVXNBKN7g5SlSdTQ5Awg76KPBwxY+83il1jBy7KA=;
        fh=k+SBmxOAVqoRVN1h1EB1nSdzXIgqk+h+f2yZExtQS7o=;
        b=IpSWWSYhdcL5Xg7Ame38sXYImJlJzTwZppFCUZ9gnOCfT20lHf/0/GquXnVf8BwBbO
         WHRtNtP+SyriN/33GKBnVTad96I4Ff4Kyy5XPb6wqU3lUFA8aPL8eXrehYBweH9krw95
         ZFeAjWhNNofJ9Sg75hQIa1TOw2bkuEfwCg6qZgCE99PSAhrczHikUUGYY4uq+zvQxKz3
         w/024yxNISO15Nv5AS6AcNlHMOLDI9jHfUjKXr6d3fq/axanHLezUKTvkuVWlxgIfOpO
         0iOA6ea5Tf9eO6ew1kM80JGq/TZGCNbH/H+wLPtt6s6PFe6e3/uakeiu/DuFmcZTalTr
         CNFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=R7jNMwCr;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755620107; x=1756224907; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=4DpuVXNBKN7g5SlSdTQ5Awg76KPBwxY+83il1jBy7KA=;
        b=VuH5sTR8IbAZM4wdy5hQYAUtGT4MucoBVIRkSQX6vVzCIgoom9klfbpVd4btKBrdRJ
         i3m6p1EIiz5nT9vJmMyQ4U/KvF0Qe1HfgCRrmEA3z9c+/j/E1L17bvjtlwZBt2OVREWQ
         gR4MzypKrNEy1hsvhSv4fS8wRAfGwwC/qam+4DEgklrhSIw5XWCYe8E571JVheZMyC+x
         KApiW0RJIkrOeMPnUqSxhhJ84E1ecu0Dz7r47qw+6YHyZuY5j1UuUgCYXbHV8dbpDXJM
         7a4w4XsldDRJCUekXGripeO1CDXzBLlzHOFqW2rEp/Pf8wEO3SP762N5iakP6bkHOOZ6
         koeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755620107; x=1756224907;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4DpuVXNBKN7g5SlSdTQ5Awg76KPBwxY+83il1jBy7KA=;
        b=J3Mg/u8u4aqHEPG7zXKUnmbq3HdoBhg01WbktVS5dxmtMw/0rEUsWHOHwE7G8vTeQI
         gmwn5wZnUI17A6NYsEjat6xLb67lVSSPLp97QMBfQ7tp6m4pm8F5WQocjdw857EyY8OK
         DBU/gRSps0Ff32D92hZwVWUvylmYs0xboX41x2ZYQ0+PT68G4RRJ+9QpknZRx9vfzgGy
         C0JfhtBHTMboKKs1KqfDRvnAGgsnWUrY2J1esb2vjAuK0FOpLpM4DNKvUeHEmhpI6wlD
         dNLJ4dBNKFqlUjC2u5+5Cauut6ujtCeKw6fpM11+4JAOKswsY3GEzgGor1fOb5eLF/hC
         QZHw==
X-Forwarded-Encrypted: i=2; AJvYcCWutxoHclw4ECf9XZd6erD3x+2CG03OnbOF3nXsFbw2NFNCi+hxGSYRYGvqmmZ+5dcdwjW0Xw==@lfdr.de
X-Gm-Message-State: AOJu0YzB479cEi4RDJV3FnUl3m/2ynHbUoD/aHTtUQY8nEK65u4e1Ls2
	6pTublEyS8iTHIH/DsZs57IwNK3HBTAlP7P46RY3zgXUgLQ0XH5IU8OW
X-Google-Smtp-Source: AGHT+IECeykRMTk8U8YESz6Ofwmec7jo1quM+MH4dUoUQXvlxqy/nK5GRBgU8hmyqUmThsFygcqLeg==
X-Received: by 2002:a05:6e02:1846:b0:3e5:40e5:bade with SMTP id e9e14a558f8ab-3e6765cff42mr59950015ab.3.1755620107054;
        Tue, 19 Aug 2025 09:15:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZffZc7XwGLINyHqAquhOsjnLQ0Szbq+rni/M5KBnIjLeA==
Received: by 2002:a05:6e02:310f:b0:3e5:842c:aa0a with SMTP id
 e9e14a558f8ab-3e5842cab91ls28550395ab.2.-pod-prod-09-us; Tue, 19 Aug 2025
 09:15:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5jT+j7fcTWuLnskh/Cgmum90gCmAmX4EyHC2Wl2yt9hnJJqntRaLWUARd5Jjd9fucRENdy2ODBuU=@googlegroups.com
X-Received: by 2002:a05:6e02:1846:b0:3e5:40e5:bade with SMTP id e9e14a558f8ab-3e6765cff42mr59948555ab.3.1755620106068;
        Tue, 19 Aug 2025 09:15:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755620106; cv=none;
        d=google.com; s=arc-20240605;
        b=exqAbBx5O+IY6Tm3/8wbwG14YxQtiWubojn6XMT4RTS2qjfiQd6pTQaWybpAMlJumV
         pmvntJ6xJ8zzebcW6c46MIzbdVKxbnAgiAH1xizQN85366thfu07ZRG2XZHqDjdyAWuK
         tQLVhxwVwJODhAlh7uFR8hBgj7HThj5jwBUPbpRW9aH1V0iM8MULES7E2dlmGXB2VlR/
         aykyeZQ8oWsaQDgoqfC+QFY2/XbTSpIub7UtKK/J2kMdIHYInDx0aCLaRMUFeSGaH9op
         XQaDK6WIQEgkz6Dnpac7mvJ4R6zVrIj4YRdCwTECuEnV4nzqgvViDd/HleADiX8ED2IM
         moJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kr+F4blUg6FODR+2BQWkkRgkHiFy8Hzr+twDnZG4NyI=;
        fh=Ika0asQmnt9ZKT9SvDFiWiNvgpsnzsdMaH2/NGTFMts=;
        b=I7pLgZ06VDwfdhpu4BEJckpZoLOZXyeFCYHM7z0sUXg3Yemsmy5KFidJ81lXG2ZBGp
         S8KWubQRzrJ6PPQADmM6CM4cS0u2DxL13TGfhLBVlhpPfDaP+AVzwmUKG6XYn0q2HVYU
         59HZXqXzo/Ol6+p6lJh94LUzX4ux4KXHqZ09UUfLX3BQ51WbEjzt/Shv1W/fAmoIetyO
         zTVLjK9BcyBgVAT2X+/n+7E5/ei402pgJE/5+hnUD4gxPyYSdTrB2+wsGNuQMtXoH4oX
         t3ZHKbTuQzmPB9oPXMXAe+TCjTmfecrwTV2iXrAUbLTPkX51lSnT9nYhCkmphD1dXb3q
         s7iA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=R7jNMwCr;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50c9454b4d2si350717173.0.2025.08.19.09.15.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 09:15:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-623-3o2EMjNHMyeBJ5Vh3nX_AA-1; Tue,
 19 Aug 2025 12:14:59 -0400
X-MC-Unique: 3o2EMjNHMyeBJ5Vh3nX_AA-1
X-Mimecast-MFC-AGG-ID: 3o2EMjNHMyeBJ5Vh3nX_AA_1755620096
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4928A180036E;
	Tue, 19 Aug 2025 16:14:56 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.95])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with SMTP id AF8BF18004A3;
	Tue, 19 Aug 2025 16:14:49 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Tue, 19 Aug 2025 18:13:37 +0200 (CEST)
Date: Tue, 19 Aug 2025 18:13:30 +0200
From: "'Oleg Nesterov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dominique Martinet <asmadeus@codewreck.org>,
	K Prateek Nayak <kprateek.nayak@amd.com>,
	syzbot <syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com>
Cc: akpm@linux-foundation.org, brauner@kernel.org, dvyukov@google.com,
	elver@google.com, glider@google.com, jack@suse.cz,
	kasan-dev@googlegroups.com, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk,
	willy@infradead.org, v9fs@lists.linux.dev,
	David Howells <dhowells@redhat.com>
Subject: Re: [PATCH] 9p/trans_fd: p9_fd_request: kick rx thread if EPOLLIN
Message-ID: <20250819161329.GC11345@redhat.com>
References: <68a2de8f.050a0220.e29e5.0097.GAE@google.com>
 <20250819161013.GB11345@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250819161013.GB11345@redhat.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=R7jNMwCr;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Oleg Nesterov <oleg@redhat.com>
Reply-To: Oleg Nesterov <oleg@redhat.com>
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

On 08/19, Oleg Nesterov wrote:
>
> Reported-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com
> Tested-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/68a2de8f.050a0220.e29e5.0097.GAE@google.com/
> Link: https://lore.kernel.org/all/67dedd2f.050a0220.31a16b.003f.GAE@google.com/
> Co-developed-by: K Prateek Nayak <kprateek.nayak@amd.com>
> Signed-off-by: K Prateek Nayak <kprateek.nayak@amd.com>
> Signed-off-by: Oleg Nesterov <oleg@redhat.com>

Prateek, I turned your "Reviewed-by" from the previous discussion
https://lore.kernel.org/all/67dedd2f.050a0220.31a16b.003f.GAE@google.com/
into Co-developed-by + Signed-off-by, I hope you won't object?

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250819161329.GC11345%40redhat.com.
