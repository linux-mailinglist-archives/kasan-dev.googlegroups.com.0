Return-Path: <kasan-dev+bncBC7OBJGL2MHBB35PYTDAMGQE4SLQMQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4119EB8FC39
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Sep 2025 11:33:37 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-45f2b0eba08sf25617515e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Sep 2025 02:33:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758533616; cv=pass;
        d=google.com; s=arc-20240605;
        b=JJuzyViUbPd3yV6lK98Y+PqPG+4/F2YnZtdPn+m2PbBpY1YH3T9Zxtp3gnwtdNilEB
         3XYz6SRRymtXNtg39H6Ltss8f7E8Bi4YS7+KZiJpBr4a6xlBcv+o5fedltwqdI3yJAAq
         9SolFywq+ZtOt8XH+cTgWVMCjHrSm1DYzFD8nnCysINdVABH3pQt+MG8JLKu4CmPl9o/
         Eph6X06682oHyud2TyODIyEGA3MOF3bgdEAd3qf0tq+vPt5X0aqwcIzvS7hGH6/0HxOs
         F/4FVjavK9e9VYntPV/S6ET4cMUq70uYnLKQJh5m0HlcaxrOG4WCwUjTP11WB7JWv8sn
         XSvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=eHpjBmhdbnzr0DZMLMbetEwpAeAUUt0XK0ILvmHCqZA=;
        fh=MJkimgeZZHRmPLg2Lz7H6UU/pwxdZGvWGXI8XQNXVok=;
        b=Jps0np0Pd1Afgubyv+t2TZlC2i55SeCrlnyAxNnEFLjJ1+Fyee+W7xLQ8NqmeQdoZb
         I5kgljQXZWHaUJRMI0hwhbjSWUdskxP1tmekpd1xqnSLqvr8Yp70OQ77wfYSE8Mxk2NQ
         Wit69v/j6dcuxro2qbH5cnuRFho2qOvOvoLpzf8nvHzE00gwWGxn0qI9JnYQjDSBGUgU
         VbS38UpjtKppM/GfNy/kW2S+YiYqw1ADqZS7zx+p2tfemY6oP2zlztFIQPqh4v8gEuG0
         fwTjTX/Df4E5QY86+xYVEF9xRTNNH2rMGIy1RDsxzHiXqGLNsQn2YoZGEAl1ZxRbni9s
         5KJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qby1G3Cb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758533616; x=1759138416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=eHpjBmhdbnzr0DZMLMbetEwpAeAUUt0XK0ILvmHCqZA=;
        b=WCzoqGQpnAbNyMpy8XauE/0ERtZujBDNStS9X1fOoTKMkRkZ4L3fefZG/s1Wt8d+Ai
         Sg5DzAgay6n6Eve118+n+9YKI2P+zTDPBOzLZ2HhmcraUTMODfQ3m8s9ZQ8RHqOT8+ds
         R+BopMomD8xMcGjsA7zY3bDhsUWn0L5TJKn+fbKjbA2sXCxFpV6S2zr+nDqK/kkReRjq
         MX0YR25NgVankP2EQT28K1LiWp4+uSAIsEadq7Wjkyki3yqxhz334s4AKKMIVmbRURVr
         dm6a+ffsK08K7e73Z7q3/p0llCPybC5Nzl0hdvaWcgbtOQGjDhnYuTikuwbo9U5nz2yl
         i3Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758533616; x=1759138416;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eHpjBmhdbnzr0DZMLMbetEwpAeAUUt0XK0ILvmHCqZA=;
        b=bpkr8PhPKsGRc8/N9OKfR4oW6Ui1j05fZgFMfoRSdkh2sbDIiJ9ouNR+9hjt0CNv1I
         qX/NnHaWyDOntK855rS4Kw/InIaWoaYCTvXFnsPwQV8BsOmP3rvTCpDRNA7Hobr3iX5D
         nsxmkgd+ls+1bAf9qLIMdESXTBGrkWPeQicw38QK7KnUcW2LifcuopaNvqM9XaIILE8c
         SvxLDSYkQvAUeW9gR9cS+AukZflFl1kKdPPSb+u6LSoG074c6PMoY6Pn8Lvt9wkGh6Xf
         1NTs3tVSbv8OHPx4D/SNjjFSfNDhJHGhXkUMQR2eaB8H9TCha5QuBcmO7Bkidev5utCN
         p8cw==
X-Forwarded-Encrypted: i=2; AJvYcCVai0k4QYpE5CtPYcW2rzDOaTly7NXuVPyaGtNVbO/RyusWcucuVhK9zcLdWrGGPS841ZEgjw==@lfdr.de
X-Gm-Message-State: AOJu0YxxoYd2Hg0fKNjgkFFswlPUJzfY/5CiOoDFuY8UoDHUa1VnxQHI
	zzYjIaHyVIoQGrXsMiyNw1AeA8us3GZwRbvwwLX3MBKHFF74xTOjPUEZ
X-Google-Smtp-Source: AGHT+IEyWUoBNpxhjwJCgDFiMzWD6nPUK4cntDXj9ETh06zeC1ox0hDauhGAdHG9iXU4YnUpkEyHrg==
X-Received: by 2002:a05:600c:c48e:b0:45d:f88f:9304 with SMTP id 5b1f17b1804b1-467ebbbfff4mr121203525e9.30.1758533616183;
        Mon, 22 Sep 2025 02:33:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5UivIZvbsk9rtbom4pIhLDGeem+zbpwUXQFITDCasCyQ==
Received: by 2002:a05:600c:46cc:b0:45b:5fbd:3012 with SMTP id
 5b1f17b1804b1-4682eea1709ls18366715e9.1.-pod-prod-01-eu; Mon, 22 Sep 2025
 02:33:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWtQGA2sgHwMLeYDi7euHe0pwYBR5BoIf/lO2NhL1RjTthrLscX2AWyo9csRayN5fvVdoBhVQbjCE=@googlegroups.com
X-Received: by 2002:a05:600c:3b11:b0:45d:d5fb:185b with SMTP id 5b1f17b1804b1-467eaf51178mr99309485e9.20.1758533613173;
        Mon, 22 Sep 2025 02:33:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758533613; cv=none;
        d=google.com; s=arc-20240605;
        b=ACyogwkwT0h0Hc8gBrkC479k62tOr01IzkhhrKdv1WgAexISuPJKcomJiZeq8RFZZy
         iYRhl0adGM5ROa/ir31YEUybYQ622K0GTScgC84gxY1ywudXtaWFjx/EwZOyRvzy3b7h
         POle4mtzIMKX1GU39vVjmTvCuu0KoyQaZzlTVkSkQMMrfoJZWH0zuj+1wdWHOqcImW6X
         1FIU5HEQ1p4ypHbwuDPitth3YxesbgdIcZ0EfU1yvJOS/5z3gWcfnoJGo3xv07JOMwof
         c5bR5vIW/9BC7As4BSE7FmIN5WoK2BdQ5grWgB6F0zRzOH1ZVr6k1uiz4aBTKWxqn/qt
         n/8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=89qPC2dMk40SQhoKG37yGCiQt/NY420sGfty0Meng0w=;
        fh=yo03+PTEVqmortuiggWD4pRjXkf7CA7qA+2zI6MnoGg=;
        b=IwcCdUO3+xkukxJW3lcU7d69dwca1LMD6qPyFS38j0yYNconKQxlQ0N5zBCjiw2Rp0
         El2ntSrOzQ7ho6BNpz3hSRJ5+xIaYUNXB3a0GTiosCdYVwjpphMLebITgaGuhOKnI0xw
         fRfiqa9PJOjT3p6sOtIbZotXesj7682bo9kWiyuGSkiUdOsa8nZoCWfU8SImSIWuGvNJ
         JNZlzyfQQSKC7DGDjwp+ObEOjGQDHe+QqvX2Ru5ACX1jYIMgzDq2TCv0eavgQoPj9Nu9
         Mtoeq80jgbqoD24JGXTC39AL2YePK23kmM89k4oNagT8s4EIDZW2BC531FNcWAGEvSay
         YjOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qby1G3Cb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-464f04eef1csi2111415e9.2.2025.09.22.02.33.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Sep 2025 02:33:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-46cf7bbfda8so5806805e9.2
        for <kasan-dev@googlegroups.com>; Mon, 22 Sep 2025 02:33:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWH6oROP7delfxqVo99/ubZ0G/N3mwvT8rj4BGSbIvus0UpKv40lkQX5F2NgP83Fl93Yzuq15MDlGI=@googlegroups.com
X-Gm-Gg: ASbGncuRqF1hn1of40pcr1papBybbZo+O9OAPIIhg9QdFWdP2JCO9my32jK254TLu5f
	QuYPTMJOtthyHHBtfJjSlKhIq814CI/nShtDUGf1BsNSNl5+coL9/a3eHfjNNeMW/NBzoDYnNps
	ZGvVRV9dNYICAT9wLvT6gbAsHd8kqu+ppvmP5cf+w+FqRd+KPEkeivtiJBbYCHLUYC+c5ox90z4
	Ltt/0+k0fs90AJmcig79r45Ye6dj9OWsF367Ax4Tdsh2kBIEy/+PjKRyB++oLvNK9zCY0qIS4mn
	K49+g8lgcWbgkLFK9QwdAUuivgfo/vVzQfo+Zc5pwGD1mf1Ud7d7HxzCzfflwgjqqsPZBr/0d+u
	UNIorPLolpPO6lBzjCgy6nQFozADIe3+BNcj03YYazL1u7+NqtnkauaS0MHc=
X-Received: by 2002:a05:600c:46c6:b0:45b:804a:a65e with SMTP id 5b1f17b1804b1-467ebbbff33mr123610355e9.28.1758533612329;
        Mon, 22 Sep 2025 02:33:32 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:2834:9:8fed:21ad:ce77:2e15])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-46d1f3e1b03sm39713145e9.23.2025.09.22.02.33.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Sep 2025 02:33:31 -0700 (PDT)
Date: Mon, 22 Sep 2025 11:33:23 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
Message-ID: <aNEX46WJh2IWhVUc@elver.google.com>
References: <20250918140451.1289454-1-elver@google.com>
 <20250918141511.GA30263@lst.de>
 <20250918174555.GA3366400@ax162>
 <20250919140803.GA23745@lst.de>
 <20250919140954.GA24160@lst.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250919140954.GA24160@lst.de>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Qby1G3Cb;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Sep 19, 2025 at 04:09PM +0200, Christoph Hellwig wrote:
> On Fri, Sep 19, 2025 at 04:08:03PM +0200, Christoph Hellwig wrote:
> > I started to play around with that.  For the nvme code adding the
> > annotations was very simply, and I also started adding trivial
> > __guarded_by which instantly found issues.
> > 
> > For XFS it was a lot more work and I still see tons of compiler
> > warnings, which I'm not entirely sure how to address.  Right now I
> > see three major classes:
> 
> And in case anyone cares, here are my patches for that:
> 
> https://git.infradead.org/?p=users/hch/misc.git;a=shortlog;h=refs/heads/cap-analysis
> 
> git://git.infradead.org/users/hch/misc.git cap-analysis

I gave this a try, and with the below patch and the Clang fix [1],
fs/xfs compiles cleanly. I think the fundamental limitation are the
conditional locking wrappers. I suspect it's possible to do better than
disabling the analysis here, by overapproximating the lock set taken
(like you did elsewhere), so that at least the callers are checked, but
when I tried it showed lots of callers need annotating as well, so I
gave up at that point. Still, it might be better than no checking at
all.

[1] https://github.com/llvm/llvm-project/pull/159921

Thanks,
 -- Marco


diff --git a/fs/xfs/xfs_inode.c b/fs/xfs/xfs_inode.c
index 9c39251961a3..f371a08e5d44 100644
--- a/fs/xfs/xfs_inode.c
+++ b/fs/xfs/xfs_inode.c
@@ -140,6 +140,7 @@ void
 xfs_ilock(
 	xfs_inode_t		*ip,
 	uint			lock_flags)
+	__capability_unsafe(/* conditional locking */)
 {
 	trace_xfs_ilock(ip, lock_flags, _RET_IP_);
 
@@ -183,6 +184,7 @@ int
 xfs_ilock_nowait(
 	xfs_inode_t		*ip,
 	uint			lock_flags)
+	__capability_unsafe(/* conditional locking */)
 {
 	trace_xfs_ilock_nowait(ip, lock_flags, _RET_IP_);
 
@@ -243,6 +245,7 @@ void
 xfs_iunlock(
 	xfs_inode_t		*ip,
 	uint			lock_flags)
+	__capability_unsafe(/* conditional locking */)
 {
 	xfs_lock_flags_assert(lock_flags);
 
@@ -272,6 +275,7 @@ void
 xfs_ilock_demote(
 	xfs_inode_t		*ip,
 	uint			lock_flags)
+	__capability_unsafe(/* conditional locking */)
 {
 	ASSERT(lock_flags & (XFS_IOLOCK_EXCL|XFS_MMAPLOCK_EXCL|XFS_ILOCK_EXCL));
 	ASSERT((lock_flags &
diff --git a/fs/xfs/xfs_log.c b/fs/xfs/xfs_log.c
index d9ac9521c203..9c4ec3aa8bf9 100644
--- a/fs/xfs/xfs_log.c
+++ b/fs/xfs/xfs_log.c
@@ -472,6 +472,7 @@ xfs_log_reserve(
 static void
 xlog_state_shutdown_callbacks(
 	struct xlog		*log)
+	__must_hold(&log->l_icloglock)
 {
 	struct xlog_in_core	*iclog;
 	LIST_HEAD(cb_list);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNEX46WJh2IWhVUc%40elver.google.com.
