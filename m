Return-Path: <kasan-dev+bncBC7OD3FKWUERB6HJUKXQMGQEMHSMTQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FC92873E73
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:24:58 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-dc64f63d768sf3712196276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:24:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749497; cv=pass;
        d=google.com; s=arc-20160816;
        b=uplmzRvmhFyr/MZJRZ+Pz5jZOWJejrusQ9sdDAWATqW6YJFr4fQcVfkRBzHlwfZLsV
         gPUdaBV2FfqrS7H6kXSwKh41/qGmHeNTCElC79u+PCRG2RkALUs0btSL8887aYyWmFK8
         wVFAYXYagaQDsC5ddnxcZdZYZ08VdnVQeHf7WxYS9tPogHPpEyHSsC1vzE6GiLL9ZZbG
         7H8uus8tn9jfBybAeNbN2OV1+TNeEd6Im5s8zEILRKCg0CKTsNIAjHlBlZQeFhBL6lwf
         dTzka+VPwJGCGzcAmKn69JMK+wr241RsfnMPF2q6TxKapCvUyv0IAfFiDvwH+WpzhC4/
         Hh4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dxMSwU6XQXMhVoge2aJ62qcdq4T0hLRb/r/lT69JSAw=;
        fh=VhPlWjofIiM9ZNdp6zNIgRXIjOEvrL/dp44H/fXPOTw=;
        b=rIOSKE0Xufli1/BokY5k+wp3JgIqPH+f7rsmgkiQ/UsbNMDcS/2Bf1Z1fFjZcbxEp4
         huItbqhZr6ZvIqXS6UMQdYwc02AAblexAVQxVH6dFEgask+IR0K6hqlsGIlQFeuCfaIL
         FKLQnrtK9cvEf2JhbrkZSP1zk/nqIYTsbUuZNzY9Pnt6bvipiS3bdKpNR3/omSH0Kok/
         +99YfUSKwh557LEtln848Do0yai6geAW2qVVLkpx+AZMDKtkWgig38+CF5P6i8cYn/BZ
         /lhMzoVJk9uLPeIPMhUFPnftBm07C+rrZ9I4ufVnHK7gFS60+vdaU/cuV4ACgDUeADtK
         6FYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zj3IzzPy;
       spf=pass (google.com: domain of 397tozqykctooqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=397ToZQYKCTooqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749497; x=1710354297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dxMSwU6XQXMhVoge2aJ62qcdq4T0hLRb/r/lT69JSAw=;
        b=EDbHvMFDUsvMpmIuTfMlVmU5NrUNrC/pI4MYV3pGareMUDV5yakwpCg584kEzGfkOn
         rqqS7CE14xIHIo+9TN8gQL/zfEkDWKZ4nuKU5W4DDD8LEEOy56S6j6jaAW4lDmgmHsqP
         /IIC0RMQ5tFL457WAgo1hxW78dpnjiZ/GksSwQ4PnGBxnIkVFRa2w0Xwq2KYjw0LD3ou
         sqFfZ1kt5+4QWGzqk+7nyB1XfDMLqtYUvNr3DwAyt7kHggq2VXtWT3dRr7C0LkbB0pQJ
         JC8jx9Qvi+mYpaiBL3ZCvvET4baGJneHjD8Ly43rej7OirHNTl6qXBG2OUZX/ZP0nyIg
         R1aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749497; x=1710354297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dxMSwU6XQXMhVoge2aJ62qcdq4T0hLRb/r/lT69JSAw=;
        b=mFjdrlbRTqSTE6EyiOu9XVl+cgTbFvu8uHMU5vETTsFRcV0WyMbEtxbLe846ReyESy
         jGEQ/QcL/Q8qauGmmsXybu6zRKpRCdlmEIHWsGRnfSUYh93OnKO9iqh63Q9oielnuW6G
         7EMjVXB0U8Y2d1YSjKkAXoS+BuS7qQAEwvvE6pwMRxHOczhs34DBsawOjRklYZ8N10bl
         NPJcuIw/RN+BBys0/0HgNHxiQlaHKJcaXko89JWGKbHlVKSem6MqFnf25MwetV8LlLv+
         hi67ijt6/fK8VHqHk63Oisk1U4SY19Wke+PoSy5i9BIDTH9cDTtd5EKM9CQU3kU16p6c
         uWXg==
X-Forwarded-Encrypted: i=2; AJvYcCUDnSemG4ypglaDbWk+ut1p5wHVUpNUeZjR6aOGs4090NTd2KHgcs7x8bD2Kwyk/XsCMMTKjIj7vcP5SMhyO5BcjmEtOAVcjw==
X-Gm-Message-State: AOJu0YwqS/aa9CC3oq0+cT/0ioy4moGoKtT74oGqOUYgLZ87UXu083Jf
	4brkHnQPjnS03hAiOz6Pbf0muO+9CxqX+1xebkG6UdH7w7IYWNe+
X-Google-Smtp-Source: AGHT+IF9TxQ8lwQI1kNNYEj+IrIZxatVJlaWI2rWGKpo2UW3wu+2PhMYk6swCWqMyjkKkKVQHGddyA==
X-Received: by 2002:a5b:810:0:b0:dc7:4692:c29 with SMTP id x16-20020a5b0810000000b00dc746920c29mr13425588ybp.33.1709749496780;
        Wed, 06 Mar 2024 10:24:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ab68:0:b0:dcb:bfe0:81b8 with SMTP id u95-20020a25ab68000000b00dcbbfe081b8ls109460ybi.0.-pod-prod-09-us;
 Wed, 06 Mar 2024 10:24:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV7PiM3yyrSuW1cFHeWaRMxxUVdrYO9tFSOaeAmP+k/E4xUKn2mMSe+lhRcAjKebVurxOctVVxtFzXgzpth1t2ClhJ28Qgwi/z90A==
X-Received: by 2002:a25:180a:0:b0:dc6:421a:3024 with SMTP id 10-20020a25180a000000b00dc6421a3024mr13495140yby.43.1709749496021;
        Wed, 06 Mar 2024 10:24:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749496; cv=none;
        d=google.com; s=arc-20160816;
        b=bn5rb5CDmV2eP4CPAqouwax4BAI9c0rfSHOPy9d+kdT6A/jDCsWc4gFJgbBVd2ypym
         Txt004kZcJBIPmSu+91osXz754QOVxhYJHqRwMdhk1Uq6eFVxphe8Q+aYBsqs08TG36D
         rtwS/nNQzkQRoYudUTl5BN/6IMJdT8Lnz4/nt6NFx7JsgObmVHnNhmGju6BQHI2yYscc
         yfiEfVDxGGXVey0iEWP1y9UU6ezaezFj3eqsjqW4Ir6bzMHY5bdi5biQitBQDF771NO9
         JUzFWyXdJwbYHYiW1V8kWeVU+SoW/HIER53F2QUhlIVjOHnhrIQ7VXgDd7ZZIpBSvDic
         SMRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/+1MAxDJuAJQyho1HAnRuoUycvJ4xPriHfVlSiFl1RY=;
        fh=N8LgTJsYrCypbChs/9ZntLidtqFjTgWbOJt0VS2xn6w=;
        b=RRzIhfZSYgUDz4AOvoztr4qGem+TKJdbLdlO05ndSVhgN3loxDrM/RD8bX/UplOjAx
         6NsjRICVlPE+WWGYiCXde6whvHY8sIMpJtFu2NYMTQk4visEf8JDyGu8XEJNjdwm5OZ2
         KoTFpoPfTDm7vYiy/dUXSvOdU94+13J7sEyL0riazA79/fTPfPMXyJa/DJ+Ldn850pdd
         0iSzSK+UYsO7RvorAOprfB1UsObUcfy5cQFPSir4DnQ3QmgbM8jcuf1LKI+JBj6BAVHT
         Z4+P0WI3rgBMu1ThXwVz4YsvWHuFEAYjdWZ+NpGX9AP/T4sCgke1IBB9Wlplq5hhmAxe
         kOXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zj3IzzPy;
       spf=pass (google.com: domain of 397tozqykctooqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=397ToZQYKCTooqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id w2-20020a25df02000000b00dc619c1f82fsi1223419ybg.4.2024.03.06.10.24.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:24:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 397tozqykctooqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dcc4563611cso11102886276.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:24:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWDeYnCmdYAPl8JlKTSwH/frLp8DCira52eJl617jt8Y1rgw2XAfMhUKB9v9jaznFctchSCSKuCfk2sk85Rai+dESfVVRxLMr0U6A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:1744:b0:dcf:6b50:9bd7 with SMTP id
 bz4-20020a056902174400b00dcf6b509bd7mr3993490ybb.7.1709749495639; Wed, 06 Mar
 2024 10:24:55 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:03 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-6-surenb@google.com>
Subject: [PATCH v5 05/37] fs: Convert alloc_inode_sb() to a macro
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zj3IzzPy;       spf=pass
 (google.com: domain of 397tozqykctooqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=397ToZQYKCTooqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

We're introducing alloc tagging, which tracks memory allocations by
callsite. Converting alloc_inode_sb() to a macro means allocations will
be tracked by its caller, which is a bit more useful.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
---
 include/linux/fs.h | 6 +-----
 1 file changed, 1 insertion(+), 5 deletions(-)

diff --git a/include/linux/fs.h b/include/linux/fs.h
index 023f37c60709..08d8246399c3 100644
--- a/include/linux/fs.h
+++ b/include/linux/fs.h
@@ -3010,11 +3010,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
  * This must be used for allocating filesystems specific inodes to set
  * up the inode reclaim context correctly.
  */
-static inline void *
-alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
-{
-	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
-}
+#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache, &_sb->s_inode_lru, _gfp)
 
 extern void __insert_inode_hash(struct inode *, unsigned long hashval);
 static inline void insert_inode_hash(struct inode *inode)
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-6-surenb%40google.com.
