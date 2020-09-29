Return-Path: <kasan-dev+bncBCS37NMQ3YHBBFX5ZX5QKGQEP2ZDNNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id DABA427D5DF
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 20:36:06 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id l9sf2086586wrq.20
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 11:36:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601404566; cv=pass;
        d=google.com; s=arc-20160816;
        b=vARIrXTDuHAmPerpcYuGw6t60W5TGgZ18Zg5uoFSw1W2RQ4N8rbaAAh2nxPAB1Stkx
         tGO3mjiOgYx68qv8GedWKhb/z9VcorgXXhwtBDiulbB5NZwULhOVJOJezT8T+IvsB7fc
         /QR8VJEPDGIH3cttIOeK/+DnvnBzZtEwViTtewB40JdRav2w29yKfA8lpU3GxPFxOC7Y
         aAHZM/3y2CKlUBelYP+7w+n0LNq1Ah3YbbHCe1laznZMH9FlJpKQF2YjnDI/EMrClPy9
         uiw4VMJ615ZzK6fnyGW8UtVcL7x3MuhgKJvAMHCPpFpM0TpsJMMawQUndrXH8mP6EP1I
         T5+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uYlBy9v8GbV2HmGQdc6TnDdIczqF/x3H047jzsUqWSE=;
        b=Orh7jwOrYceRd5I1j4cBJg6gBIprBRDRwo6Jl4vERoqVNXpTRUMZcwarMnDU0QLhRF
         TuSx6iYPVEqGoXbwtoC5nPxa3o3exIOYoYuRvXezmK3YgXE7fnFAgg+WCkpfJ5IGRWCt
         9P2BtPWkw62qRClWDJIBJWkD62k+4UdTIKIBdwl9F/H/f9CU602Gcc5VBbLqkkYB7Au8
         mftb3Ff/xXwhMdMG3DfkfJXhzNgnl7qn7Z/Qy8Oa0PYWfuofxUcsU/YQk6qK3d6QnsZh
         LoWWn9pNvLC7H3GNRBpJDp+aRSqzfm574lfgeLAQ+0MulblzZl5Pe1FLLC6via/nZ4fy
         tuyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uYlBy9v8GbV2HmGQdc6TnDdIczqF/x3H047jzsUqWSE=;
        b=QtHT82UuWFoiPFDEqee9R//Cmq67KEkAnxtyAsG6kSHrm4G6tWdL3jzOkK6dB+Srbh
         zkMzYLb+u89rF0Tk7VsDv+i8SQ6x0JzrvLrXJ2QoE0RT5NG2nhdvrilR3SC29KJZjkxR
         QjiYH+fv99L+U5JdIYBaA9NM80ipf6+KpkcCPGupeMQ7HHRpb/v2WScpGEXnGNOdxOe6
         pBGHln4QUBjRYZ2cH+5TYVmlcbZRCItyyW+Oev7JaOjlTKKPLwhW8vxKqdzOJZTRCh83
         rANEMNhYTDscD5VpJdZXOl+d/BzKLkDPXiSHZpnr8qK8Du21XCe9JQ6+I7lKJlRY/bSj
         0L9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uYlBy9v8GbV2HmGQdc6TnDdIczqF/x3H047jzsUqWSE=;
        b=I42HNgz46LBcWKTaIJwI+btExy+5NpNCqqk4ghQb6sK99ZBjGjaM49uGgQ2tnJkwwv
         MMdnMCNREWZucZiCminuzrCzkMFu1fFl994VDvPnfhWHxmKdvWJAHiQdk452qp5Eyi12
         fLMZ9dzEtpT/4Q95PK4iCzbjEUGCem5F82sBuUoCduijDEWHfEUFKDc2k655qS2Ehkn8
         IHULROO2qEuODyZwj1uICRrEWHoMXff+MrE2Jagx0762sqRC30eZNLtscvuT68nQLsN/
         OYI58zDKWLzjhCdZSMUFxxOMQnuakMPfTDt7yZVBPitXbP/3MjSVdA5nETxaXQ/8TrAZ
         /Lpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532LgrTrWARljbteQ/tnrD8CyDWuTNh/kwL+ZHywITCC5ABt5SrI
	cTH+IlSigLqAGanikEAyjnY=
X-Google-Smtp-Source: ABdhPJy6JSvuXVM+iyfd0J0gwBsd+KBs9j4wB2mfGr1eqwkfYvmJo860AeqC2Mu6Qujf9wLYCw18Cg==
X-Received: by 2002:adf:f6c8:: with SMTP id y8mr6209091wrp.217.1601404566593;
        Tue, 29 Sep 2020 11:36:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2e58:: with SMTP id u85ls2274828wmu.2.gmail; Tue, 29 Sep
 2020 11:36:05 -0700 (PDT)
X-Received: by 2002:a1c:20ce:: with SMTP id g197mr6186005wmg.72.1601404565777;
        Tue, 29 Sep 2020 11:36:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601404565; cv=none;
        d=google.com; s=arc-20160816;
        b=LDK23WMZvnveGUaQFvIPj+CyWlk/8s9j7UFIon16V5F0c/M/rNRROtJVyOwrjbkySo
         Y31doVj0MNodaU2bWWVk0o5d7gTGARhROpevYJddnQpNsxvotnHoz350A0RnrJTHzFmR
         qfbcKVnAZxqO4SzxB4LgmBc0Hr/UjktOJvQRxJDln4FRoMpTFLE9bq9vfS9uMOy5/zTR
         xkGkRoYulx9ErG94dRm49EY2Rjun4/ZBG048z1y2l61jKHU7DqjskxLTDdsG9daB/AC8
         pkHigfiR1iM7wAx5xnm2IF8ki8HDPtUcpMYLExOD6rEqSiEo11TCr9ydDbDFl8rZ49lU
         m/gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=G75o1vtwJEJqsn4jLLLjWPJ87JkHTslNJiSKbRH/W+U=;
        b=Jj1Cuyi1AuKwClnpYgkJQJaI5FiVzdoikAr8Dh+533V22f2yX+GWU6ZcpFxGqdlwo7
         3u8JSei879hzUgaiGJo5iZuHO6mbk04p5sInKx2yClRitvZCHBKCyaay2U7SKCbfLEvI
         BLtkyi7wkGxsto89QDNTlhowW5RFPzDTiTHJejILF/wL6gdb2Bv/d4i5gFeffZWe5iTY
         nZlGHtWGSFP+A0x1vahRbLqVROQIhtAW5CbBMTQNq71hFuILyWYf37YBlkHgk6ranpci
         qlhRMKf3vw4DranwrEFs8/9+57cUt3NjsuKCl4A2INjP1hsU3hiRYuZotPhEHExY1+We
         WwJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f67.google.com (mail-wr1-f67.google.com. [209.85.221.67])
        by gmr-mx.google.com with ESMTPS id z17si295051wrm.2.2020.09.29.11.36.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 11:36:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) client-ip=209.85.221.67;
Received: by mail-wr1-f67.google.com with SMTP id o5so6522759wrn.13
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 11:36:05 -0700 (PDT)
X-Received: by 2002:adf:e58b:: with SMTP id l11mr6203909wrm.210.1601404565480;
        Tue, 29 Sep 2020 11:36:05 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id b188sm12151271wmb.2.2020.09.29.11.36.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 11:36:04 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
To: Kees Cook <keescook@chromium.org>,
	Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Matthew Wilcox <willy@infradead.org>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC v2 6/6] mm: Add heap quarantine verbose debugging (not for merge)
Date: Tue, 29 Sep 2020 21:35:13 +0300
Message-Id: <20200929183513.380760-7-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200929183513.380760-1-alex.popov@linux.com>
References: <20200929183513.380760-1-alex.popov@linux.com>
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Content-Type: text/plain; charset="UTF-8"
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

Add verbose debugging for deeper understanding of the heap quarantine
inner workings (this patch is not for merge).

Signed-off-by: Alexander Popov <alex.popov@linux.com>
---
 mm/kasan/quarantine.c | 21 +++++++++++++++++++++
 1 file changed, 21 insertions(+)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 4ce100605086..98cd6e963755 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -203,6 +203,12 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 		qlist_move_all(q, &temp);
 
 		raw_spin_lock(&quarantine_lock);
+
+		pr_info("quarantine: PUT %zu to tail batch %d, whole sz %zu, batch sz %lu\n",
+				temp.bytes, quarantine_tail,
+				READ_ONCE(quarantine_size),
+				READ_ONCE(quarantine_batch_size));
+
 		WRITE_ONCE(quarantine_size, quarantine_size + temp.bytes);
 		qlist_move_all(&temp, &global_quarantine[quarantine_tail]);
 		if (global_quarantine[quarantine_tail].bytes >=
@@ -313,7 +319,22 @@ void quarantine_reduce(void)
 			quarantine_head = get_random_int() % QUARANTINE_BATCHES;
 		} while (quarantine_head == quarantine_tail);
 		qlist_move_random(&global_quarantine[quarantine_head], &to_free);
+		pr_info("quarantine: whole sz exceed max by %lu, REDUCE head batch %d by %zu, leave %zu\n",
+				quarantine_size - quarantine_max_size,
+				quarantine_head, to_free.bytes,
+				global_quarantine[quarantine_head].bytes);
 		WRITE_ONCE(quarantine_size, quarantine_size - to_free.bytes);
+
+		if (quarantine_head == 0) {
+			unsigned long i;
+
+			pr_info("quarantine: data level in batches:");
+			for (i = 0; i < QUARANTINE_BATCHES; i++) {
+				pr_info("  %lu - %lu%%\n",
+					i, global_quarantine[i].bytes *
+						100 / quarantine_batch_size);
+			}
+		}
 	}
 #endif
 
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929183513.380760-7-alex.popov%40linux.com.
