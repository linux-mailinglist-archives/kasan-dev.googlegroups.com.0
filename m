Return-Path: <kasan-dev+bncBCS4VDMYRUNBBJUMV2XQMGQEZGQYMGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id B0654876C79
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 22:42:00 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5d8bcf739e5sf2102446a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Mar 2024 13:42:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709934119; cv=pass;
        d=google.com; s=arc-20160816;
        b=CbMLKn4if4Cp5eY6JqqJynor9KgPuwNjgXZ2KIIfT1P3G9Njgk1tPdQL4/CoGZvrFI
         Dv5uoSR7ODdkZoBmWM5JGZl76e+JbO3iHsMrzhrT9BejFd8PAl02PR7YbNC93sskmHnV
         eHl/Dz/QyE8Dykj3WOE6YQcCg1E07Hom76yflns/l7vfnmyS/R022u11OIUUD0UWpLAs
         iCeL+Mh4b/dqo6eVALoAzl0BYdkTupZ/WPep2iy+oKQnk9rMchLlcIu2ka5LJvjPkTmh
         4zFSFqJtWZKBnxb0Q6wd7lV9LcW/6s0fi/FBvxIjq4RtzOniIJKXv0bN5ocoqq6R1aQZ
         4q3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qtBkTxRyFhT7OwQpyywLO77I61h+U2+6leS3ICOtKfs=;
        fh=TmxGhth/DISpdUKrJQ5wF1ZVVSvH3IVrO4y6Ywjd3Uw=;
        b=SWW1RezE6JnGdrtEfXYAvhJAjyOa3RUpgyuNJnUx+ZnRfWgE8vbaQlf6KAhb+25JdU
         PVTozbApdr38yNBWtXMF/9lQMmi7mwZt0VecmGngcCXtr9e4+JU1K9XCTXFGRMb2eGYI
         LbTe54btohIRNITqQjIn2h2jh2Z4IaBZA+eliLnq4dLWSDoQYq+fqn5TSDdplX9lz5Sp
         5ustweQByioy5jaQNOi0/K6XItsHH9W+ozpgM1/twxjSHmshqcLL4ZNP0YpdQRtwL2lK
         2yZ3dm02CruEBprpq3NREabRBYxEhg15gOz4OnXtU51pczNvry0BptkoV2fUErw8hTEh
         r7YQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gnlLM7nz;
       spf=pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709934119; x=1710538919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qtBkTxRyFhT7OwQpyywLO77I61h+U2+6leS3ICOtKfs=;
        b=L3qKXgWp59w3rI4w/b8HVn5OIJOnGez5QmYyGEyRFq1McNKZMY3DJqso6LmJyoVksf
         uruQ0ezHaVxyRc3OHj+XDCA2RZKn9da+Iq0GqTGbUuZMP+yUqOsIib+vQCxFUApMgNts
         JyE4JKJ7z/C454SC6KyucQq9aUIPtcE1m8g2W6GfTbgOh3g1Fli8GCc943E3I8gikVvL
         9k6C4pllQlN48fP+h/74cX2SZrm3vyiiHJMfUQ+webO4lPHpBT3N3WD0Y5ICjHOX0rrT
         Hah8+7UJ2X/SV1+kOlue9vDRylxjeEmk3QtYmB8xH5xq/Ug/d/o021LJ8cIKR+z9Ti3+
         RCcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709934119; x=1710538919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=qtBkTxRyFhT7OwQpyywLO77I61h+U2+6leS3ICOtKfs=;
        b=axaazEDI48Zgqa8Gh+xtVNlX31PfuuGUirH8qbwQmsyfqPXXKggyToqndvbL52dt26
         mCbhGUDVLcGRyRKbbyngs2kiw+zED8cjYUN94WAkJcLrDnw1s7mSJuP2XChqZxixORrq
         dsgjtPVi+DmP+X99+68JOKZ7XQHaLatrVJg/d/VRv567/BcfTXfFXuw8FvX/ztF5GQZd
         l8798PuxrAzK5G3n8RzJ3elDNDv1D/RfITm2n6eKbWEJsfQQLxh1UR1MpgKOn+06Onkb
         JW2hURxoQNZqNuXpyusxqjle/TEqICOVQUKlfvKV2tZ0HipfThZdphovjtE0QYfBIvDx
         ZZeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWABWmfMlviH0tZ9f/s8AdpOKKpiJ2SjhcetSS2fJ3m9ydbiig4Ke3K0mZdyOiFR6wwT9jB25vTw/PjdFXB61/b17MKp3M5Ww==
X-Gm-Message-State: AOJu0YxWMYcL5MIoIj9+fFuCwQ395InUjeK/lRJYuHintGV/e7gPHspT
	wI/P+EKY75VaX3RLKjEMPIXXj/+LjPnaLmwBOZKIYLimLm4yyEci
X-Google-Smtp-Source: AGHT+IEen329Y4Bx8W/U1ckSq7RpwyP1+1I4UFv8gjrBQscYuxk0nqyLqgDUGufMFlFL4nK9eSG+ww==
X-Received: by 2002:a17:90a:ff0d:b0:299:8ff:40c0 with SMTP id ce13-20020a17090aff0d00b0029908ff40c0mr412576pjb.28.1709934118800;
        Fri, 08 Mar 2024 13:41:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:164d:b0:29b:a97e:255f with SMTP id
 il13-20020a17090b164d00b0029ba97e255fls786169pjb.0.-pod-prod-09-us; Fri, 08
 Mar 2024 13:41:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUa7rZh2KFJE4xeUQJN2pGwKJfIiqEwDmOZVdsirnmDZwjqtonfsjHwGGxmC+qykfSHvYSOLykV2ZjLqw7R3FHOHq0cv+uf5qaYLA==
X-Received: by 2002:a17:90a:460c:b0:29a:7125:11a1 with SMTP id w12-20020a17090a460c00b0029a712511a1mr400673pjg.41.1709934117392;
        Fri, 08 Mar 2024 13:41:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709934117; cv=none;
        d=google.com; s=arc-20160816;
        b=KnBK3RDbCF1k/HqT8WIWn0vWVeaS5dq4FPQPs5O9GrlE4LXExQnnN3/mKUS+QcON0e
         YJ2DpMfHQjfK9z/kI5BfL5g3XGUmudzjdS0km+38uFnrk2y/TZJTgp0SaDltjcBYcmlt
         yS1z0Ug2Nirc5zZPL3M3cduESrACiFZ9hgldoI/2TTurxZErl+eMAbcz06w5Qyo9U259
         XT9RCifX4jiP0hAxnBTGcYxLMimoDkE5sjZ7YWXAs+vDzVxRS1ZQ5oaiVMYpajgjNzGo
         vUnvdRBXKMuG1ZD8tAf7L7lHidgNtcsmmBFFLJChoapKZU/o8r09RF6iqxz8MTk5Xd+g
         mBUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=SwQ/6fVTq+Z4GKPA/MwWk4g8oTjVYzos6YRI2HZfdr4=;
        fh=U7bngLKXwjC96+8wLhDziHbfLLhg9lj94uYgnEc2mZw=;
        b=W3D+eTRr/M84q90HZku9Qo6F8nl2N7nt+kXx6UFN8PKRALW6d7vS8FaMSInubEPrnm
         GJ0ahjeKP/CIEWr0a+KJfSGg8SSGxvA9S+TD/BxtnGCwRE+Fq3y45p+jVuiRN1swcA7d
         n45D/oSUqp4O5vzAbdA/fnOw1w11NC0gwpNdXYdSRWPl18PjIWgNrwMRcAuuiTKdPGhX
         q8zng1zlzOFZ5XLTaddbTumlLtgg2Bd3Xhh8eeYHPs7gvmZmno8m9MOIJRB5SgilMtfz
         1TP2wiraOGMDEY9DMK6+6lMke0ufVA9lfp3mQdHKdhqXpGxEuNM2MSHkYySx4v+GR5SZ
         wnBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gnlLM7nz;
       spf=pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id ay14-20020a17090b030e00b0029b9a141bbesi371109pjb.3.2024.03.08.13.41.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Mar 2024 13:41:57 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 3CFEDCE1D97;
	Fri,  8 Mar 2024 21:41:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7D1FEC433F1;
	Fri,  8 Mar 2024 21:41:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 24B91CE0548; Fri,  8 Mar 2024 13:41:54 -0800 (PST)
Date: Fri, 8 Mar 2024 13:41:54 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: elver@google.com
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, dvyukov@google.com,
	glider@google.com
Subject: [PATCH RFC rcu] Inform KCSAN of one-byte cmpxchg() in
 rcu_trc_cmpxchg_need_qs()
Message-ID: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gnlLM7nz;       spf=pass
 (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Tasks Trace RCU needs a single-byte cmpxchg(), but no such thing exists.
Therefore, rcu_trc_cmpxchg_need_qs() emulates one using field substitution
and a four-byte cmpxchg(), such that the other three bytes are always
atomically updated to their old values.  This works, but results in
false-positive KCSAN failures because as far as KCSAN knows, this
cmpxchg() operation is updating all four bytes.

This commit therefore encloses the cmpxchg() in a data_race() and adds
a single-byte instrument_atomic_read_write(), thus telling KCSAN exactly
what is going on so as to avoid the false positives.

Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>

---

Is this really the right way to do this?

diff --git a/kernel/rcu/tasks.h b/kernel/rcu/tasks.h
index d5319bbe8c982..e83adcdb49b5f 100644
--- a/kernel/rcu/tasks.h
+++ b/kernel/rcu/tasks.h
@@ -1460,6 +1460,7 @@ static void rcu_st_need_qs(struct task_struct *t, u8 v)
 /*
  * Do a cmpxchg() on ->trc_reader_special.b.need_qs, allowing for
  * the four-byte operand-size restriction of some platforms.
+ *
  * Returns the old value, which is often ignored.
  */
 u8 rcu_trc_cmpxchg_need_qs(struct task_struct *t, u8 old, u8 new)
@@ -1471,7 +1472,13 @@ u8 rcu_trc_cmpxchg_need_qs(struct task_struct *t, u8 old, u8 new)
 	if (trs_old.b.need_qs != old)
 		return trs_old.b.need_qs;
 	trs_new.b.need_qs = new;
-	ret.s = cmpxchg(&t->trc_reader_special.s, trs_old.s, trs_new.s);
+
+	// Although cmpxchg() appears to KCSAN to update all four bytes,
+	// only the .b.need_qs byte actually changes.
+	instrument_atomic_read_write(&t->trc_reader_special.b.need_qs,
+				     sizeof(t->trc_reader_special.b.need_qs));
+	ret.s = data_race(cmpxchg(&t->trc_reader_special.s, trs_old.s, trs_new.s));
+
 	return ret.b.need_qs;
 }
 EXPORT_SYMBOL_GPL(rcu_trc_cmpxchg_need_qs);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0733eb10-5e7a-4450-9b8a-527b97c842ff%40paulmck-laptop.
