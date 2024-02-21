Return-Path: <kasan-dev+bncBC7OD3FKWUERBVND3GXAMGQECV6PEAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id E964C85E76F
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:10 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1dc0e27ea7dsf146555ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544469; cv=pass;
        d=google.com; s=arc-20160816;
        b=OJykugMoVXjpNjyRJfmDh6X03aGu0s31oFnMCROgEJ+K18r7FAYv7fIK7GoPwbugO7
         NkteEGE5VuwnMosE+xZmlvQDOFEDd3u/hNdF2K0HhiBK7d671WfOIR0hgLXSg4yM04Kq
         8/4v3Kc1PmpOaYgHJtvOxWJgC9Pi9aqf4muymkxGbfy3GVUwE4OtqCCRh8ayaL5IScTw
         OZzwaWOl1x22f4ta9OhajnaGLloRpif6dtIeFD5fNdlUbxDEXQrrLLsRbehNhVPJs0hC
         3+ChIDDnkmd2+cMRCltnWCy4QY0EiM/m/SAQL0fkP0VAl0oTsNAYxq+bAuSHQ9IEIf+6
         zsbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=XGaz/w58L8C0VqJqEoJcNNLYdPmeSeKJ0feHSNfMvrI=;
        fh=p6QqA+aXvnq48qBmJjR3LzHSgPAdwKR4sdZ+Ys+Nn1I=;
        b=DHArbSoQS0Pno52eTbQJyHlP6goQ44AG1Bvtw9f+tQlDzcDXdPVkNkW8SPkjfIsR0x
         /MICnkBQKlgiOK8eOb4BdGEY4bFH/OnYAmhunvrfyV4/5x33pzHp6e9ibrL5FSTyNXej
         UBkm94z97LfoglAPV2unrXm+PVP1THCEOqbdSPxy1LxgkgAYvpElXvz2cWkj514pXS14
         urqefJWiGuxl7D3MMyc1yCH6g3+9f0g4+1W0XKeSkNRybB+CVeDYlwCirEhipWb/i0o5
         zk+1qXqXRwZjBJYCOSZQIEhVq/OazRToR2rU0ZuIwLLMSswgzhUw9g03eHyjlVnNRi2m
         fffg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QfeLPT0H;
       spf=pass (google.com: domain of 301hwzqykcqyy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=301HWZQYKCQYy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544469; x=1709149269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XGaz/w58L8C0VqJqEoJcNNLYdPmeSeKJ0feHSNfMvrI=;
        b=EM+ZslWex0Y/7J4uQzrFBF7V7q74sZxc6SvJq4wjtbIUGeYYp6WHAHM3iQ7en73e60
         i7i9tDzPZMatxxqKphCCohCGpYXXItO07nZAFviEg+cYxhoy+BZ8bEmKXb29zyTZmQEK
         CBuR7p31DGdrlvD80F3yzZZANafTZngj8n6CX1WaSCcKb3Zhct1arHidjLfN/UvN3FaS
         u/7AZYACma+QfUkZ8wKxVhpZHaIUaFW5VeQENSlBYo4nsBeSHTZ0RrAptDe/qTc5BXyO
         484LB3tf9+AoZot76X3t/5nIDWrwXaCSRfsipX9v0knUOEx6FITH0Ai3fwE4vI49VUbd
         zh9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544469; x=1709149269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XGaz/w58L8C0VqJqEoJcNNLYdPmeSeKJ0feHSNfMvrI=;
        b=pID0deQk0KfRog+0I2LbykbY6rLI5MulwbhqmXEfSSAGvKhKId8dlyknd8cyRPO0v3
         kbI6CvUQ/PUgl+f7dJ/13ToD5CyCJRcAYFRtIP0lB5f8es51mErb8/XRS7WzvpudSpNW
         mwX3ZjKbWqkbVGgIAsbU/oKRBU9Qgh/mrP7ESLPeWl9Hakv6z+YQo0RDhb/bBSM8MQDt
         akr7VR+131P5opzXpFEL5/9AIWpt14qQEPdmxYQDufamrm5ZCZ4BlaDAYVpt+dkjxMgK
         /5/APIPqZLpfdLumRRFl2QEDi8lO5teWWDYmGzmAxL2yz/ZXk/QIyk4jfHx5wotcRY3v
         pn/g==
X-Forwarded-Encrypted: i=2; AJvYcCX70enkoQeTj7vAdd5eRaNCuUGwEh6rG9QK0wU65wDpDfT600Cl5WxZzOIxtYmXID3uETkrBhoh8EaxxrFloBCwAPd046Zg4Q==
X-Gm-Message-State: AOJu0Yyq3wxNJxtW6293nlobij/v4fykeiaadoyZOaOBmlHcyPuUXteW
	eWB/u80YModB2FzO83NzjhDbHroWqs/joouAfiUgY8bs1f9pyQ1s
X-Google-Smtp-Source: AGHT+IFHZ5DlLUf3Ll5f6CN1AcPLWsfr3ynuYxwO4MuwmJ+OPRNqzegaV3ETPRkAGcW+p0kPo/JH5A==
X-Received: by 2002:a17:902:ce91:b0:1db:a6be:ddc6 with SMTP id f17-20020a170902ce9100b001dba6beddc6mr261737plg.27.1708544469481;
        Wed, 21 Feb 2024 11:41:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ab8b:0:b0:598:6f4a:c095 with SMTP id m11-20020a4aab8b000000b005986f4ac095ls5940346oon.1.-pod-prod-09-us;
 Wed, 21 Feb 2024 11:41:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVIsssoo2bI65yAGym1ICMfjeCEtuGx0zNafN/KHkChknkaH3NHwjlQAjOoNcx87txzIfid5KdPKy3OErgMLA2vcj05eZp/uNDKyw==
X-Received: by 2002:a05:6359:4c07:b0:178:75b1:c403 with SMTP id kj7-20020a0563594c0700b0017875b1c403mr20675050rwc.9.1708544468470;
        Wed, 21 Feb 2024 11:41:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544468; cv=none;
        d=google.com; s=arc-20160816;
        b=DmzY9k5OhtQ0MVsbU2kfP8DKuEQutZtozndQmt5z7g/qrcuifurQmR0hVQh7gmjd6Z
         sS2lpnuMHJS/P61bRGSEMExgt7aDr9iL2tr42NSd6I+dOuCvehrr+RYD90x9WaTyw35r
         ItbAj8EEanzZfJ0dvmnuyBgBSd4PZCL0vRE0Vb6hxROAZu0EdeiSMkQmAJgwFsPrjNpd
         gc+qmjDSmjZ17ZgjAbaQySoi1Gq11KgxY2kM98D25SP5qm4Jr2yedx7N7L7tPRgkrNYZ
         9X345IlgIzaFdTleIliit7C/C6CuvbSB5nNBV+fiEVnimJz6+0jEKWf0JuCLtLYVKjoX
         nOMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=14sostfgXdBtkigrgclSIrhsv4NljUYVKVXEohyvFzI=;
        fh=mKTpCPfSP5DDlTagD9tbKBSsml5VnETNpp2yeg4CTcY=;
        b=n3fZwbiHrWuPnmaO4BVJMXu9CpvsZqJPa/Doc6nzJ8iPyN434ksPi1szejYe8XXRWl
         3KUkrUXzDI+vaqcrnRbs7R143+Z98uuoIITAEWsduZb9c1zxofkRj2O7jfoJUFKOKEdp
         VeBAconFaWvOBrWpRgnYDHGKcHgHZG8GljOLm4pWbOhjudsL0tOknpg9Ge8nrRszgwNn
         9l4RS6LT2eI/ed2TCwrzv9KHE0maNIvrqB/FRQ1hQbD/AOuY08pgF7il70VB1YHhK3Aw
         QlEDvm2sX2+OXrwRCuTvb9/X9ENT1wlzsNpQC+afnFmcbea5XkGe59S2YIki585C0SbI
         898g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QfeLPT0H;
       spf=pass (google.com: domain of 301hwzqykcqyy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=301HWZQYKCQYy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id p16-20020a056a000b5000b006e49fcb1e28si149430pfo.5.2024.02.21.11.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 301hwzqykcqyy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6082ad43ca1so60767877b3.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXplKqt8larywpgJ4OPd/iGNzJoj+HALeilKrS7/vyZy91aBiRP9cJ/dB3f4PnQaiCMb/KSl13TQkeeZeCrT2CQ7E9dIWk8ag06aQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:4c2:b0:dcc:4785:b51e with SMTP id
 v2-20020a05690204c200b00dcc4785b51emr10314ybs.12.1708544467498; Wed, 21 Feb
 2024 11:41:07 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:18 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-6-surenb@google.com>
Subject: [PATCH v4 05/36] fs: Convert alloc_inode_sb() to a macro
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
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QfeLPT0H;       spf=pass
 (google.com: domain of 301hwzqykcqyy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=301HWZQYKCQYy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-6-surenb%40google.com.
