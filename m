Return-Path: <kasan-dev+bncBC2JFQ6TUUPRBT5G4GOAMGQEOC4CLMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 521EC64B335
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 11:26:24 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id d6-20020adfa346000000b0024211c0f988sf2792792wrb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 02:26:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670927184; cv=pass;
        d=google.com; s=arc-20160816;
        b=S4UK/R+Gh3z8ZoHTIAr+in0V8U6CQ1f7BOprO4S8HIt+sTCl1uhdTqXZTOXNcdjZnR
         MTa8tqh8Z/n3D5p+/EGNgwhvEBnWQlC4bzNTh1ucM/T5JX5Pl/Uw56EcacfZiWuPH+Ci
         egvo6I3qdFTByNl3+hYqbPTtH784P8kGLdJOom+HWttWNdwZIPFg1vPaHj9uK2o+YJyy
         N0BFNo8UZucfkNkesDQ82dzP1jVBY+9mBBvEJpKuqhtGwb5Ir0EyTZwPjiHLaW+um4nh
         YSRfuHCpPXw1LnzCEFE22qUTJSqhVMEM7ADKtTvOcXJwLvsaNwA5yG770trXJBn+SOv+
         Ji8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=iUr6NOP3pq/p1kRyK1dhwy15Yj4NypM8xLZeqtqDLP4=;
        b=l3WBYx3r1rviz/QyI44k/s1EMRJCBs/pvMuDwfAFWSHldS8syXyh11Cou+bXnmoCRY
         VAqq+vz6YICNnACBBong71+Q9ok3YeIJMHL1JXJ3njq3zEwxKzQ83MyDkOYqXnY66CMk
         D9bPmg00FA0HakoYpBqKzPpbNwM1aDtJARGfpcXGTMhx4ER+Cp97tNlViMD/JpmhngZ0
         +2q6yVcDY4YkZG1/RAOx4OtitTo6IQ1cL/ah3SUaV/SpAopADhQGgVRRdjD0A5RuPKBQ
         3Bbnq1P/Bki6Jtt4C1URhTsBtVzmor+x5CoS/1ZoiWrjzBBO+haEE0K1foe71cttlUSk
         DfIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=W7Kv1xxP;
       spf=pass (google.com: domain of sudipm.mukherjee@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=sudipm.mukherjee@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iUr6NOP3pq/p1kRyK1dhwy15Yj4NypM8xLZeqtqDLP4=;
        b=T8XtVbXJriL9dstZvFB7oTzu5ywRk/YKxIqwwiJaq2XJVW8eyRwBawVilWEMT/Z/+5
         XjSCLmkTq+7lmQ5FcGtsYwSBU9ZDQEGYfa1IEcdJpfOLThWPX21mNxEmHAXBF03Esfbt
         Wz4wS+w+45MwZud6S8kivK9WNtyXemUMEzjiyrBgiK2BkLMLJYh34pIjnmkNhufK3neJ
         O8evxFw3R1+BHh5Cg0tZubJmofXqQ2SDFEVnWJCgQOuGQvXs6Wu7Ezpk8qxKB4V04w7z
         FtBHDwf8JRj50ptLgxkp2m+TZa0msLVBtr5u7asO7t8DiZUdemdeK4B0nsjWLEyRtx+F
         J6zg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=iUr6NOP3pq/p1kRyK1dhwy15Yj4NypM8xLZeqtqDLP4=;
        b=OPEkwruXbLDicrEhJP5Sp5TnPH26Mh9Cj+NlrfNFHSsEQs9eiw9wzhhKP5JPlNsvXl
         2LTJIqSXg8dnBqSlmV++tdpYdcM72Q5C08+ibDiDvoqvbMSWLs9yHpKxjvTU80mbRaQ5
         59uKX1T9+QvWa0G3DNepjJd4KuHSl6cDe1fzYlPxn9ugWRTjXw9X8iybXOsTBHg0B/F9
         lSRuubLTlamqJR2uUYlVOvV50WVY0cOJZF4voe1YimI0ZVEvrbD4Y40jZffVppMerzJo
         RCz6J3u4mEiZbU0jddn5lDgqTgww2T9OuxudTFqjV0qFkpW0vq75n0XahZqHa//s74kc
         QnEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iUr6NOP3pq/p1kRyK1dhwy15Yj4NypM8xLZeqtqDLP4=;
        b=DkEi3Bk9sePYDHE8NC2dn9x31H0exUnYS0xdZT9ZktQBScTx1EFOkf1jF6y8LwK4uO
         y1FacngkTAFXqPO+8nDXJRfGOo5i82TXcJhTpMxl3GTVwt0vq/baTB5mlCVdogH1MYIt
         t/kgqQU7zcXBzsRiUT6ELu9mkjUpJQl4rBweQhd13QryH4eTKDII5ijhGXRkAWYkj8jw
         4qEaAVVPQy5bTlR9GDtLzb0e6yz1n0J9h4Q6Ni62UGJjAwzNE2dnAAP/vrjcnbHoB/zB
         YBoYieyDIIdvdg6mmu14CXtNiq/bXfjZlfuBv4fRShenQc2Q8gBbh97iSMrjcr4R3TmO
         Z3DQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkwDcDlnuk+vVqU4wd+Ri1x6OQzl9BUeDExpJU1jbWktTSo6OZo
	l36vJOrLS093VXfXL5eWciY=
X-Google-Smtp-Source: AA0mqf4eS7OgScp7vjNbxjA/cx3PI5WA+4tDiBX18yn45zLHl8gSV/Nwlvy1iUMpMxosr6OcCE3bVQ==
X-Received: by 2002:a05:600c:15c2:b0:3d2:1991:a1f3 with SMTP id v2-20020a05600c15c200b003d21991a1f3mr167848wmf.170.1670927183922;
        Tue, 13 Dec 2022 02:26:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fd87:0:b0:236:8fa4:71d1 with SMTP id d7-20020adffd87000000b002368fa471d1ls10635790wrr.1.-pod-prod-gmail;
 Tue, 13 Dec 2022 02:26:22 -0800 (PST)
X-Received: by 2002:a5d:614f:0:b0:242:45fe:72f with SMTP id y15-20020a5d614f000000b0024245fe072fmr12489350wrt.56.1670927182504;
        Tue, 13 Dec 2022 02:26:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670927182; cv=none;
        d=google.com; s=arc-20160816;
        b=lBwUhcXjFscoagqe4YVjFUg0xoUWFzy6u3IJcE7LpwjM6HExRcGMaSHT/e+4LAsQQ9
         /VkN3MRRqZ56oUyYrmltM6Fa+tc7+CRAy9b3n1E14f+kUVPBq4kVkqoWX+59M4ppYGEx
         Eplj68WAmwxV/VZOmijYMy7SOPvUYQfA0nM1BI25nhyCkVj7HeJVnOS3IrmY/ICyvugr
         MNq9R9cyDUXcH7qbnAGVLEYlruilyo2belxvO0bRWB+oCcn2HJ4Q0llSG4dGDyiWCz2Y
         z6OlZ2P7vXN0GA65W7Ew5nIpHFfUul5QDyxuBw+MCbFhDUBQ+Pne8uKMCHzEtK4qM+ap
         +mnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Pu08UoEEhSuGsocqugEAMUYroTyoru7RTTvNi/xK32k=;
        b=0MXmjN23n7ZbGoLOs3taFidmB98+e/PFMOipEz/tLeP0PcbiHW8VKpkJRuzD+XecsV
         UL/aR0TrcVvANZYwln8f5qG9/04yg0IcaKWhaEomzcAdFGHI+Dk3crWH5p/cM6AXqgbJ
         alCg9Wt/1hWi9m1Ik0P+7Oqp/tzaFkdj+SRU2C5N3V+BKyjnnUBMyZr759e6ncoGJ6Ev
         9alKACi8kpXecYanm0z0fjzwNb6ThtRVcl3EdM3pava7y8H6iWKrIwsSYNCezxS9BK0G
         GaVaJrBXOuzRI36UTcdX8DKUbHoNBd8GjYWHVvqkTKviQHQnvAFG1bLGrUllI8gfnIec
         LTTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=W7Kv1xxP;
       spf=pass (google.com: domain of sudipm.mukherjee@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=sudipm.mukherjee@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id bj15-20020a0560001e0f00b002367b2e748esi590096wrb.5.2022.12.13.02.26.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Dec 2022 02:26:22 -0800 (PST)
Received-SPF: pass (google.com: domain of sudipm.mukherjee@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id ay14-20020a05600c1e0e00b003cf6ab34b61so7500906wmb.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Dec 2022 02:26:22 -0800 (PST)
X-Received: by 2002:a05:600c:4fc8:b0:3cf:b067:4142 with SMTP id o8-20020a05600c4fc800b003cfb0674142mr14942913wmq.4.1670927182014;
        Tue, 13 Dec 2022 02:26:22 -0800 (PST)
Received: from debian (host-78-150-37-98.as13285.net. [78.150.37.98])
        by smtp.gmail.com with ESMTPSA id o25-20020a05600c511900b003c6f8d30e40sm13471412wms.31.2022.12.13.02.26.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Dec 2022 02:26:21 -0800 (PST)
Date: Tue, 13 Dec 2022 10:26:20 +0000
From: "Sudip Mukherjee (Codethink)" <sudipm.mukherjee@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Linus Torvalds <torvalds@linux-foundation.org>
Subject: mainline build failure due to e240e53ae0ab ("mm, slub: add
 CONFIG_SLUB_TINY")
Message-ID: <Y5hTTGf/RA2kpqOF@debian>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: sudipm.mukherjee@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=W7Kv1xxP;       spf=pass
 (google.com: domain of sudipm.mukherjee@gmail.com designates
 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=sudipm.mukherjee@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi All,

The latest mainline kernel branch fails to build xtensa allmodconfig 
with gcc-11 with the error:

kernel/kcsan/kcsan_test.c: In function '__report_matches':
kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]
  257 | }
      | ^

git bisect pointed to e240e53ae0ab ("mm, slub: add CONFIG_SLUB_TINY")


I will be happy to test any patch or provide any extra log if needed.

Note:
This is only seen with gcc-11, gcc-12 builds are ok.

-- 
Regards
Sudip

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y5hTTGf/RA2kpqOF%40debian.
